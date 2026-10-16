# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Writes binary64_known_answers.txt beside this script, for binary64_test.exs.

Each line is a JSON number and the binary64 value nearest it, ties to even, as Python's
float() reads it. CPython's float() is correctly rounded for a decimal of any length, and
each answer is checked again here with exact rational arithmetic (fractions.Fraction) for
every number of at most 20,000 characters. Run it with python3 from any directory; with the
same seed it writes the same file.

A line is tab-separated: the answer, then either the number itself, or four fields head,
fill, count and tail for the number head + fill * count + tail, which keeps a number of a
quarter of a million digits to one short line. The answer is the 16 lowercase hex digits of
the value's IEEE 754 bits, or `overflow` when the nearest value is an infinity.
"""

import math
import os
import random
import re
import struct
import sys
from decimal import Decimal, getcontext
from fractions import Fraction

sys.set_int_max_str_digits(0)
getcontext().prec = 3000

SEED = 20260928
GRAMMAR = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?\Z")
MAX_FLOAT = sys.float_info.max
TWO_1024 = Fraction(2) ** 1024
OVERFLOW_AT = TWO_1024 - Fraction(2) ** 970
LONG = 262_000

rng = random.Random(SEED)
lines = []
seen = set()


def bits(value):
    return struct.pack(">d", value).hex()


def from_bits(pattern):
    return struct.unpack(">d", pattern.to_bytes(8, "big"))[0]


def answer(text):
    value = float(text)
    return "overflow" if math.isinf(value) else bits(value)


def exact_answer(text):
    """The nearest binary64 value by exact arithmetic, ties to even, for the self-check."""
    q = Fraction(text)
    negative = q < 0 or text.startswith("-")
    q = abs(q)
    if q >= OVERFLOW_AT:
        return "overflow"
    if q == 0:
        return bits(-0.0 if negative else 0.0)
    exponent = q.numerator.bit_length() - q.denominator.bit_length()
    lsb = max(exponent - 53, -1074)
    while lsb > -1074 and q < Fraction(2) ** (lsb + 52):
        lsb -= 1
    while q >= Fraction(2) ** (lsb + 53):
        lsb += 1
    scaled = q / Fraction(2) ** lsb
    floor = scaled.numerator // scaled.denominator
    rest = scaled - floor
    if rest > Fraction(1, 2) or (rest == Fraction(1, 2) and floor % 2 == 1):
        floor += 1
    value = math.ldexp(floor, lsb)
    return bits(-value if negative else value)


def add(head, fill="", count=0, tail=""):
    text = head + fill * count + tail
    assert GRAMMAR.match(text), text[:80]
    key = (head, fill, count, tail)
    if key in seen:
        return
    seen.add(key)
    expected = answer(text)
    exponent = GRAMMAR.match(text).group(3)
    small_exponent = exponent is None or len(exponent.lstrip("eE+-").lstrip("0")) <= 4
    if len(text) <= 20_000 and small_exponent:
        assert exact_answer(text) == expected, text[:80]
    if count == 0:
        lines.append(f"{expected}\t{text}")
    else:
        lines.append(f"{expected}\t{head}\t{fill}\t{count}\t{tail}")


def plain(d):
    """A Decimal written with no exponent, in the JSON grammar."""
    text = format(d, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".") if d == d.to_integral_value() else text
    return text


def scientific(d):
    """A Decimal written with every significant digit and an exponent."""
    return format(d, "e")


def with_point(text):
    return text if "." in text else text + ".0"


def halfway(low, high):
    return (Decimal(low) + Decimal(high)) / 2


def halfway_cases(low, high, long=False):
    """The halfway point between two adjacent values, exactly and just either side."""
    h = halfway(low, high)
    # Three places past the last digit of h.
    step = Decimal(1).scaleb(h.normalize().as_tuple().exponent - 3)
    write = plain if h.adjusted() >= -20 else scientific
    add(write(h))
    add(scientific(h))
    add(write(h + step))
    add(write(h - step))
    # The digits with a point, and what follows them: nothing, or the exponent.
    if h.adjusted() >= -20:
        digits, suffix = with_point(plain(h)), ""
    else:
        mantissa, exponent = scientific(h).split("e")
        digits, suffix = with_point(mantissa), "e" + exponent
    # Just above by a digit far past the 800th, a tie spelled with trailing zeros, and just
    # below: the final 5 made 4, then nines.
    counts = [900, LONG] if long else [900]
    for count in counts:
        add(digits, "0", count, "1" + suffix)
        add(digits, "0", count, suffix)
        if digits.endswith("5"):
            add(digits[:-1] + "4", "9", count, suffix)


def neighbours(value):
    return value, math.nextafter(value, math.inf)


def random_double(max_biased=2046):
    biased = rng.randint(0, max_biased)
    fraction = rng.getrandbits(52)
    return from_bits((biased << 52) | fraction)


def the_crash_inputs():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "strtod_crash_inputs.txt")) as f:
        for line in f.read().splitlines():
            if line and not line.startswith("#"):
                add(line)


# The edges: zero, the subnormals, the smallest normal, and the largest values.
for text in ["0", "-0", "0.0", "-0.0", "0e0", "0E+0", "-0e-5", "0e99999999999999999999"]:
    add(text)

smallest = from_bits(1)
largest_subnormal = from_bits((1 << 52) - 1)
smallest_normal = from_bits(1 << 52)
halfway_cases(0.0, smallest, long=True)
halfway_cases(smallest, from_bits(2))
halfway_cases(largest_subnormal, smallest_normal, long=True)
halfway_cases(smallest_normal, from_bits((1 << 52) + 1))
halfway_cases(math.nextafter(MAX_FLOAT, 0.0), MAX_FLOAT)

for value in [smallest, from_bits(2), from_bits(3), largest_subnormal, smallest_normal, MAX_FLOAT]:
    add(plain(Decimal(value)))
    add(scientific(Decimal(value)))
    add(repr(value).replace("e+", "e"))

# 2^1024 - 2^970, halfway between the largest value and 2^1024: a tie that rounds to the
# even 2^1024, an infinity. Just below it is the largest value.
edge = Decimal(2) ** 1024 - Decimal(2) ** 970
add(plain(edge))
add(scientific(edge))
add(plain(edge) + ".", "0", 900, "1")
add(plain(edge - 1))
add(plain(edge - 1) + ".", "9", 900)
add(plain(edge - 1) + ".", "9", LONG)
add(plain(edge) + ".", "0", LONG)
add(plain(Decimal(2) ** 1024))
for text in [
    "1.7976931348623157e308",
    "1.7976931348623158e308",
    "1.7976931348623159e308",
    "1.797693134862315807e308",
    "1.797693134862315808e308",
    "-1.7976931348623158e308",
    "1e308",
    "9.9999999999999999e308",
    "1e309",
    "1e400",
    "-1e400",
    "1e-323",
    "1e-324",
    "2.4703282292062327e-324",
    "2.4703282292062328e-324",
    "2.5e-324",
    "4.9406564584124654e-324",
    "7.4109846876186981e-324",
    "7.4109846876186982e-324",
    "9.99e-325",
    "2.2250738585072011e-308",
    "2.2250738585072012e-308",
    "2.2250738585072014e-308",
    "4.9e-324",
    "5e-324",
    "1e-400",
    "-1e-400",
]:
    add(text)

# Exponents with many digits, and digits whose leading zeros the exponent makes up.
for text in [
    "1e" + "0" * 30 + "308",
    "1e+" + "0" * 30 + "309",
    "1e-" + "0" * 40 + "5",
    "1e" + "9" * 20,
    "1e-" + "9" * 20,
    "-1e" + "9" * 20,
    "1e999999999999999",
    "1e-999999999999999",
    "1e9999999999999999",
    "1e-9999999999999999",
    "0." + "0" * 500 + "1e501",
    "0." + "0" * 500 + "17976931348623157e809",
    "0." + "0" * 500 + "17976931348623159e809",
    "0." + "0" * 300 + "24703282292062328e-23",
    "123456789" + "0" * 400 + "e-400",
    "1" + "0" * 308,
    "1" + "0" * 309,
    "9" * 309,
    "9" * 400,
]:
    add(text)
add("1e", "0", LONG, "5")
add("1e-", "0", LONG, "1")
add("1e", "9", 30)
add("0.", "0", LONG, "1")
add("0.", "0", LONG, "1e262001")
add("1", "0", LONG)
add("-1", "0", 290, "e-300")

# The crash inputs of macOS 27's strtod, and long spellings of their kind: an integer or
# half an integer followed by hundreds of nines, or of zeros and a final digit.
the_crash_inputs()
for _ in range(200):
    integer = rng.choice(
        [rng.randint(1, 10**6), rng.randint(2**52, 2**54), rng.randint(2**62, 2**64), 10**16 - 2]
    )
    length = rng.randint(150, 750)
    sign = rng.choice(["", "-"])
    kind = rng.randint(0, 3)
    if kind == 0:
        add(f"{sign}{integer}.", "9", length)
    elif kind == 1:
        add(f"{sign}{integer}.4", "9", length)
    elif kind == 2:
        add(f"{sign}{integer}.5", "0", length, str(rng.randint(1, 9)))
    else:
        add(f"{sign}{integer}.", "0", length, str(rng.randint(1, 99_999)))

# Halfway points between adjacent values across the whole range, most of moderate size.
def random_moderate():
    return from_bits((rng.randint(1023 - 70, 1023 + 70) << 52) | rng.getrandbits(52))


for _ in range(300):
    halfway_cases(*neighbours(random_moderate()))
for _ in range(40):
    low = random_double()
    if low < MAX_FLOAT:
        halfway_cases(*neighbours(low))
for _ in range(20):
    halfway_cases(*neighbours(random_double(40)))
# Adjacent values around a power of two, where the spacing halves below it.
for exponent in [-1022, -1000, -500, -60, -1, 0, 1, 52, 53, 60, 500, 1000, 1023]:
    power = math.ldexp(1.0, exponent)
    halfway_cases(math.nextafter(power, 0.0), power)
    halfway_cases(*neighbours(power))

# Exact decimal values of doubles, their shortest spellings and spellings of 17, 20 and 25
# significant digits.
for _ in range(500):
    value = (random_moderate() if rng.random() < 0.9 else random_double()) * rng.choice([1, -1])
    add(plain(Decimal(value)) if abs(value) >= 1e-30 else scientific(Decimal(value)))
    add(repr(value).replace("e+", "e"))
    for digits in (17, 20, 25):
        add(f"{value:.{digits - 1}e}")

# Random digit strings of every length up to 1,200, with random exponents.
for _ in range(700):
    length = rng.choice([rng.randint(1, 20), rng.randint(20, 40), rng.randint(40, 1200)])
    digits = str(rng.randint(1, 9)) + "".join(rng.choice("0123456789") for _ in range(length - 1))
    point = rng.randint(1, length)
    exponent = rng.randint(-340, 320) - point + 1
    sign = rng.choice(["", "-"])
    mantissa = digits[:point] + ("." + digits[point:] if point < length else "")
    add(f"{sign}{mantissa}e{exponent}")

# Integers near 2^53 and 10^21, where J5 draws its lines.
for n in [2**53 - 1, 2**53, 2**53 + 1, 2**53 + 2, 2**53 + 3, 2**54 + 2, 10**21 - 1, 10**21,
          10**21 + 1, 2**64 - 1, 2**64 + 2048]:
    add(str(n))
    add(str(n) + ".0")
    add(str(n) + ".", "0", 800, "1")

here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "binary64_known_answers.txt"), "w", newline="\n") as f:
    f.write("# Copyright (c) 2026 Truestamp, Inc.\n")
    f.write("# SPDX-License-Identifier: Apache-2.0\n")
    f.write("#\n")
    f.write("# Written by binary64_known_answers.py (Python's float()); see that script.\n")
    for line in lines:
        f.write(line + "\n")
print(f"wrote {len(lines)} answers")
