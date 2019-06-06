# -*- coding: utf-8 -*-
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

from typing import Union, List, Dict, Iterable, Type, Any

from crash.infra.lookup import SymbolCallback
from crash.subsystem.storage import block_device_name

import gdb

EndIOSpecifier = Union[int, str, List[str], gdb.Value, gdb.Symbol, None]

class Decoder(object):
    """Decoder objects are used to unwind the storage stack

    They are relatively lightweight at runtime, meaning that the object
    is initialized but not decoded until it's needed.  The string will
    be formatted each time, but each :obj:`.Decoder`'s :func:`interpret()`
    method will be called once.

    Attributes:
        interpreted (:obj:`bool`): Whether the contents of this
            :obj:`.Decoder` have already been interpreted
    """
    __endio__: EndIOSpecifier = None

    # pylint: disable=unused-argument
    def __init__(self, value: gdb.Value = None) -> None:
        self.interpreted = False

    def interpret(self) -> None:
        """
        Interpret the :obj:`.Decoder` object

        Rather than populate all the fields when they may not be used,
        we delay interpreting the object until the fields are needed.

        This method will examine the object passed to the derived class's
        constructor and produce the attributes required for each object.
        """
        pass

    def __getattr__(self, name: str) -> Any:
        if self.interpreted:
            raise AttributeError(f"No such attribute `{name}'")

        self.interpret()
        self.interpreted = True
        return getattr(self, name)

    @classmethod
    def register(cls) -> None:
        """
        Registers a decoder with the storage decoder subsystem.

        Each :obj:`.Decoder` contains the name of an endio routine.  When
        an object that needs decoding is encountered, the endio
        routine contained in the object is used to look up the decoder
        for that object.
        """
        register_decoder(cls.__endio__, cls)

    def __str__(self) -> str:
        """
        The printable description of this :obj:`.Decoder`.  Typical
        :obj:`.Decoder`s include the address of the object, the block
        device it uses, and the location(s) affected by the object.
        """
        pass

    def __next__(self) -> Any:
        """
        For stacked storage, the object may have been generated as part
        of an operation on another object.  e.g. a bio generated by
        buffer_head submission, a request generated by bio submission,
        a bio generated by another bio being cloned by device mapper, etc.

        In these scenarios, the __next__ method can be used to pass the
        next :obj:`Decoder` object in the chain.  It is not necessary to know
        the source of the object being decoded -- only its type is
        necessary.

        Typical uses will be ``return decode_bh(self.bh)`` or
        ``return decode_bio(self.next_bio)``

        If there are no objects beyond this one, it does not need to be
        overridden.
        """
        pass

class BadBHDecoder(Decoder):
    """
    Placeholder decoder for bad buffer_head pointers

    Rather than raise a :obj:`gdb.NotAvailableError` during decoding, we use a
    :obj:`.BadBHDecoder` decoder to annotate where in the chain there was an
    invalid buffer_head.

    Args:
        bh: The ``struct buffer_head`` to be decoded.  The value must be of
            type ``struct buffer_head``.

    Attributes:
        bh (:obj:`gdb.Value`): The ``struct buffer head`` that was
            referenced from the bio.  The value is of type
            ``struct buffer_head``.
    """
    _description = "{:x} bh: invalid buffer_head"

    def __init__(self, bh: gdb.Value) -> None:
        super().__init__()
        self.bh = bh

    def __str__(self) -> str:
        return self._description.format(int(self.bh))

class GenericBHDecoder(Decoder):
    """
    Decodes a bio that references a ``struct buffer_head``

    This method decodes a generic ``struct buffer_head``, when no
    implementation-specific decoder is available

    Args:
        bh: The ``struct buffer_head`` to be decoded.  The value must be of
            type ``struct buffer_head``.

    Attributes:
        bh (:obj:`gdb.Value`): The ``struct buffer head`` that was
            referenced from the bio.  The value is of type
            ``struct buffer_head``.
    """

    _description = "{:x} buffer_head: for dev {}, block {}, size {} (undecoded)"

    def __init__(self, bh: gdb.Value) -> None:
        super().__init__()
        self.bh = bh

    def interpret(self) -> None:
        # pylint: disable=attribute-defined-outside-init
        self.block_device = block_device_name(self.bh['b_bdev'])

    def __str__(self) -> str:
        return self._description.format(int(self.bh), self.block_device,
                                        self.bh['b_blocknr'], self.bh['b_size'])

_decoders: Dict[int, Type[Decoder]] = dict()

def register_decoder(endio: EndIOSpecifier, decoder: Type[Decoder]) -> None:
    """
    Registers a bio/buffer_head decoder with the storage subsystem.

    A decoder is a class that accepts a bio, buffer_head, or other object,
    potentially interprets the private members of the object, and
    returns a :obj:`.Decoder` object that describes it.

    The only mandatory part of a :obj:`.Decoder` is the :meth:`__str__`
    method to format the description.

    If the bio is part of a stack, the :meth:`__next__` method will contain
    the next :obj:`.Decoder` object in the stack.  It does not necessarily need
    to be a bio.  The :obj:`.Decoder` does not need to be registered unless it
    will be a top-level decoder.

    Other attributes can be added as-needed to allow informed callers
    to obtain direct information.

    Args:
        endio: The function(s) used as endio callback(s).

            The :obj:`str` or :obj:`list` of :obj:`str` arguments are used
            to register a callback such that the :obj:`.Decoder` is
            registered when the symbol is available.

            The :obj:`gdb.Symbol`, :obj:`gdb.Value`, and :obj:`int` versions
            are to be used once the symbol is available for resolution.

            If in doubt, use the names instead of the :obj:`gdb.Symbol` objects.

        decoder: The decoder class used to handle this object.

    """
    debug = False
    if isinstance(endio, str):
        if debug:
            print(f"Registering {endio} as callback")
        SymbolCallback(endio, lambda a: register_decoder(a, decoder))
        return
    elif isinstance(endio, list) and isinstance(endio[0], str):
        for sym in endio:
            if debug:
                print(f"Registering {sym} as callback")
            SymbolCallback(sym, lambda a: register_decoder(a, decoder))
        return

    if isinstance(endio, gdb.Symbol):
        endio = endio.value()

    if isinstance(endio, gdb.Value):
        endio = int(endio.address)

    if debug:
        print(f"Registering {endio:#x} for real")

    _decoders[endio] = decoder

class BadBioDecoder(Decoder):
    """
    Placeholder decoder for bad bio pointers

    Rather than raise a :obj:`.NotAvailableError` during decoding, we use a
    :obj:`.BadBioDecoder` decoder to annotate where in the chain there was an
    invalid bio.

    Args:
        bio: The bio to decode.  The value must be of type ``struct bio``.

    Attributes:
        bio (:obj:`gdb.Value`): The bio being decoded.  The value is of
            type ``struct bio``.
    """
    _description = "{:x} bio: invalid bio"

    def __init__(self, bio: gdb.Value) -> None:
        super().__init__()
        self.bio = bio

    def __str__(self) -> str:
        return self._description.format(int(self.bio))

class GenericBioDecoder(Decoder):
    """
    Placeholder decoder for when we have a valid bio but nothing to decode it

    Args:
        bio: The bio to decode.  The value must be of type ``struct bio``.

    Attributes:
        bio (:obj:`gdb.Value`): The bio being decoded.  The value is of type
            ``struct bio``.
    """
    _description = "{:x} bio: undecoded bio on {} ({})"
    def __init__(self, bio: gdb.Value) -> None:
        super().__init__()
        self.bio = bio

    def __str__(self) -> str:
        return self._description.format(int(self.bio),
                                        block_device_name(self.bio['bi_bdev']),
                                        self.bio['bi_end_io'])

def decode_bio(bio: gdb.Value) -> Decoder:
    """
    Decodes a single bio, if possible

    This method will return a :obj:`.Decoder` object describing a single bio
    after decoding it using a registered decoder, if available.

    If no decoder is registered, a generic decoder will be used.

    If an invalid object is encountered, a handler decoder will be used.

    Args:
        bio: The bio to decode.  The value must be of type ``struct bio``.

    Returns:
        :obj:`.Decoder`: The decoder appropriate for this bio type.
    """

    try:
        return _decoders[int(bio['bi_end_io'])](bio)
    except KeyError:
        return GenericBioDecoder(bio)
    except gdb.NotAvailableError:
        return BadBioDecoder(bio)

def decode_bh(bh: gdb.Value) -> Decoder:
    """
    Decodes a single buffer_head, if possible

    This method will return a :obj:`.Decoder` object describing a single
    ``struct buffer_head`` after decoding it using a registered decoder,
    if available.

    If no decoder is registered, a generic decoder will be used.

    If an invalid object is encountered, a handler decoder will be used.

    Args:
        bh: The buffer_head to decode.  The value must be of type
            ``struct buffer_head``.

    Returns:
        :obj:`.Decoder`: The decoder appropriate for this buffer_head type
    """
    try:
        return _decoders[int(bh['b_end_io'])](bh)
    except KeyError:
        return GenericBHDecoder(bh)
    except gdb.NotAvailableError:
        return BadBHDecoder(bh)

def for_each_bio_in_stack(bio: gdb.Value) -> Iterable[Decoder]:
    """
    Iterates and decodes each bio involved in a stacked storage environment

    This method will yield a Decoder object describing each level
    in the storage stack, starting with the provided bio, as
    processed by each level's decoder.  The stack will be interrupted
    if an encountered object doesn't have a decoder specified.

    Args:
        bio: The initial struct bio to start decoding.  The value must be
            of type ``struct bio``.

    Yields:
        :obj:`.Decoder`: The next :obj:`.Decoder` in the stack, if any remain.
    """
    decoder = decode_bio(bio)
    while decoder is not None:
        yield decoder
        try:
            decoder = next(decoder)
        except StopIteration:
            break
