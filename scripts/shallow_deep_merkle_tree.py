#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import itertools

from rich.console import Console
from rich.table import Table

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

sns.set_context('poster')

INFINITY = 9999999999999

#OTS_SIZE = 592  # w=16
OTS_SIZE = 405  # w=64
#OTS_SIZE = 320  # w=256
HASH_SIZE = 16

FALCON_SIZE = 512
FAILURE_RATE = 0.5

FORESTS = [
    [0, 1, 2, 3, 7],
    [2, 7],
    [0, 0, 0, 0, 0, 0, 0, 0, 7],
    [0, 0, 0, 0, 7],
    [0, 0, 0, 7],
    [0, 0, 7],
    [0, 0, 0, 0, 5, 5, 5, 5],
    [0, 1, 2, 3, 4, 5, 6],
    [0, 1, 2, 7],
    [0, 1, 7],
    [0, 2, 7],
    [0, 3, 7],
    [1, 2, 7],
    [1, 3, 7],
    [2, 3, 7],
    [3, 3, 7],
    [0, 3, 3, 7],
    [0, 7],
    [1, 7],
    [2, 7],
    [3, 7],
]

# without Merkle tree

SIZE = (1-FAILURE_RATE) * OTS_SIZE + FAILURE_RATE * FALCON_SIZE
print(f'Sig size w/o tree: {SIZE} B')
print('PK size w/o tree: 897 B')
print()

def merkle_forest(heights, fail_rate):
    costs = [h + (i+1) for (i, h) in enumerate(heights)]

    # calculate probabilities for landing in each tree
    probs = [0 for _ in heights]
    index = 0
    for (tree, h) in enumerate(heights):
        for e in range(index, index + 2 ** h):
            probs[tree] += (1-fail_rate) * fail_rate ** e
        index += 2 ** h

    sigs = sum(2 ** h for h in heights)
    min_size = OTS_SIZE + costs[0] * HASH_SIZE
    avg_size = OTS_SIZE + sum([c * probs[i] for (i, c) in enumerate(costs)]) * HASH_SIZE
    max_size = OTS_SIZE + costs[-1] * HASH_SIZE
    avg_time = sum(2 ** h * probs[i] for (i, h) in enumerate(heights))
    return (sigs, min_size, avg_size, max_size, avg_time)

def cost_function(forest):
    (sigs, min_size, avg_size, max_size, avg_time) = merkle_forest(forest, 0.001)
    cost_01 = cost_function_single(sigs, min_size, avg_size, max_size, avg_time)
    (sigs, min_size, avg_size, max_size, avg_time) = merkle_forest(forest, 0.01)
    cost_1 = cost_function_single(sigs, min_size, avg_size, max_size, avg_time)
    (sigs, min_size, avg_size, max_size, avg_time) = merkle_forest(forest, 0.1)
    cost_10 = cost_function_single(sigs, min_size, avg_size, max_size, avg_time)
    (sigs, min_size, avg_size, max_size, avg_time) = merkle_forest(forest, 0.2)
    cost_20 = cost_function_single(sigs, min_size, avg_size, max_size, avg_time)
    (sigs, min_size, avg_size, max_size, avg_time) = merkle_forest(forest, 0.5)
    cost_50 = cost_function_single(sigs, min_size, avg_size, max_size, avg_time)
    return (cost_01 + cost_1 + cost_10 + cost_20 + cost_50) / 5.0

def cost_function_single(sigs, min_size, avg_size, max_size, avg_time):
    if sigs < 128:
        return INFINITY
    return avg_size
    #sigs_cost = (sigs - 128) * 10
    #size_cost = min_size + 1000 * (avg_size-min_size) + 10*(max_size-min_size)
    #time_cost = avg_time
    #return sigs_cost + size_cost + time_cost

# find Merkle forest which optimizes cost function

opt_forest = None
opt_cost = INFINITY
for r in range(1, 6):
    for forest in list(itertools.combinations_with_replacement([0, 1, 2, 3, 4, 5, 6, 7], r)):
        cost = cost_function(forest)
        if cost < opt_cost:
            opt_cost = cost
            opt_forest = forest

print('-'.join(map(str, opt_forest)), 'was the best Merkle forest found, with a cost of:', opt_cost)

# with shallow-deep Merkle tree

console = Console()
table = Table(show_header=True, header_style='bold cyan')
table.add_column('Parameters')
table.add_column('Num sigs', justify='right')
table.add_column('Sig size (Min)', justify='right')
table.add_column('Sig size (Avg)', justify='right')
table.add_column('Sig size (Max)', justify='right')
table.add_column('Avg. sig time', justify='right')

for s in range(0, 5):
    for d in range(7, 9):
        sigs = 2 ** s + 2 ** d

        #d_chance = FAILURE_RATE ** (2 ** s)
        d_chance = FAILURE_RATE ** (2 ** s)

        auth_path_len = (1-d_chance) * 0 + d_chance * d

        num_s_pubs = d_chance * (2 ** s)
        for e in range(0, 2 ** s):
            num_s_pubs += e * (1-FAILURE_RATE) * (FAILURE_RATE ** e) / (1-d_chance)

        min_size = OTS_SIZE + 1 * HASH_SIZE
        avg_size = OTS_SIZE + (1 + num_s_pubs) * HASH_SIZE + auth_path_len * HASH_SIZE
        max_size = OTS_SIZE + (1 + 2 ** s) * HASH_SIZE + d * HASH_SIZE

        #gen_time = (1-FAILURE_RATE) * (2 ** s) + FAILURE_RATE * (2 ** d)
        gen_time = 1 + d_chance * (2 ** d)

        table.add_row(f's={s}, d={d}',
                      str(int(sigs)),
                      f'{min_size:.1f} B',
                      f'{avg_size:.1f} B',
                      f'{max_size:.1f} B',
                      f'{gen_time:.2f} OTS', end_section=(s==4 and d==8))

for mf in FORESTS:
    (sigs, min_size, avg_size, max_size, sig_time) = merkle_forest(mf, FAILURE_RATE)
    name = '-'.join(map(str, mf))
    table.add_row(name,
                  str(int(sigs)),
                  f'{min_size:.1f} B',
                  f'{avg_size:.1f} B',
                  f'{max_size:.1f} B',
                  f'{sig_time:.2f} OTS')

console.print(table)

# sd-Merkle graph

# number of layers of the deep subtree to cache on the authenticator
CLIENT_SIDE_CACHING = 2

s_col = []
d_col = []
fail_rate_col = []
sig_time_col = []
sig_size_col = []

for s in range(0, 5):
    d = 7
    #for d in range(7, 9):
    for fail_rate in [i / 1000.0 for i in range(0, 1000)]:
        s_col.append(s)
        d_col.append(d)
        fail_rate_col.append(fail_rate)
        d_chance = fail_rate ** (2 ** s)
        sig_time_col.append(1 + d_chance * (2 ** (d-CLIENT_SIDE_CACHING)))

        num_s_pubs = d_chance * (2 ** s)
        for e in range(0, 2 ** s):
            num_s_pubs += e * (1-fail_rate) * (fail_rate ** e) / (1-d_chance)

        cost = 1 + num_s_pubs + (1-d_chance) * 0 + d_chance * d
        sig_size_col.append(OTS_SIZE + cost * HASH_SIZE)

df = pd.DataFrame(data={
    's': s_col,
    'd': d_col,
    'fail_rate': fail_rate_col,
    'sig_time': sig_time_col,
    'sig_size': sig_size_col,
})

grid = sns.FacetGrid(df, col='s', row='d')
grid.map(plt.plot, 'fail_rate', 'sig_time', color='black')
plt.ylim([0, 80])
plt.show()

grid = sns.FacetGrid(df, col='s', row='d')
grid.map(plt.plot, 'fail_rate', 'sig_size', color='black')
plt.ylim([0, 1000])
plt.show()
