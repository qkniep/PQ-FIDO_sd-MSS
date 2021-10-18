#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from math import log2
import random
from statistics import median

X = 10_000_000


print('-- Sum digits --')
probabilities = [0 for _ in range(129)]

for _ in range(X):
    sis = [0 for _ in range(16)]
    for i in range(512 // 4):
        hex_d = random.getrandbits(4)
        for d in str(i + 1):
            sis[hex_d] += int(d)
        sis[hex_d] %= 128
    for hex_d in range(16):
        probabilities[sis[hex_d]+1] += 1 / X / 16

max_pos, max_val = max(enumerate(probabilities), key=(lambda x: x[1]))
print(f'Expected probability: {1 / 128}')
print(f'Max probability: [{max_pos}] {max_val}')
print(f'Median probability: {median(probabilities)}')
print(f'Sum of probabilities: {sum(probabilities)}')
print(f'WC Security Level: {-log2(max(probabilities) ** 16)}')
print(f'Max theoretical SL: {int(log2(128 ** 16))}')


print('\n-- Sum numbers (m=512, mod 128) --')
probabilities = [0 for _ in range(129)]

for _ in range(X):
    sis = [0 for _ in range(16)]
    for i in range(512 // 4):
        hex_d = random.getrandbits(4)
        sis[hex_d] += i
        sis[hex_d] %= 128
    for hex_d in range(16):
        probabilities[sis[hex_d]+1] += 1 / X / 16

max_pos, max_val = max(enumerate(probabilities), key=(lambda x: x[1]))
print(f'Expected probability: {1 / 128}')
print(f'Max probability: [{max_pos}] {max_val}')
print(f'Median probability: {median(probabilities)}')
print(f'Sum of probabilities: {sum(probabilities)}')
print(f'WC Security Level: {-log2(max(probabilities) ** 16)}')
print(f'Max theoretical SL: {int(log2(128 ** 16))}')


print('\n-- Sum numbers (m=512, mod 256) --')
probabilities = [0 for _ in range(257)]

for _ in range(X):
    count = [0 for _ in range(16)]
    sis = [0 for _ in range(16)]
    for i in range(512 // 4):
        hex_d = random.getrandbits(4)
        sis[hex_d] += i
        sis[hex_d] %= 256
        count[hex_d] += 1
    for hex_d in range(16):
        if count[hex_d] == 0:
            sis[hex_d] = random.getrandbits(8)
        probabilities[sis[hex_d]+1] += 1 / X / 16

max_pos, max_val = max(enumerate(probabilities), key=(lambda x: x[1]))
print(f'Expected probability: {1 / 256}')
print(f'Max probability: [{max_pos}] {max_val}')
print(f'Median probability: {median(probabilities)}')
print(f'Sum of probabilities: {sum(probabilities)}')
print(f'WC Security Level: {-log2(max(probabilities) ** 16)}')
print(f'Max theoretical SL: {int(log2(256 ** 16))}')
