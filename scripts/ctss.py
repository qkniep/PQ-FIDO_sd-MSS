#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from math import ceil, log2

from rich.console import Console
from rich.table import Table

#SHA256_HASHRATE = 7407  # nRF52840-DK - Software
SHA256_HASHRATE = 7407 * 46 #812500  # nRF52840-DK - Cryptocell 310
#SHA256_HASHRATE = 10_989_000  # my laptop (AMD Ryzen 5 4600H)

FALCON_PK_SIZE=897

# WOTS parameters
W = 16
X = 2
N = 128 / 8
M = N
L1 = M * X
L2 = 3  # L2=2 for both N=128/8 and N=256/8
L = L1 + L2

def xmss_wots(height, cached_layer):
    sigs = 2 ** height
    # +1 for public key, +1 for bitmask seed
    sig_size = (L + 1 + 1 + height) * N
    keygen_calls = L * W * (2 ** height)
    keygen_time = keygen_calls / SHA256_HASHRATE
    #sign_calls = L * (W / 2) * 2 ** (height-cached_layer)
    sign_calls = L * W * 2 ** (height-cached_layer)
    sign_time = sign_calls / SHA256_HASHRATE
    client_state = 2 ** cached_layer * N + N
    server_state = N
    return (
        f'XMSS (h={height}, c={cached_layer})',
        str(int(sigs)),
        f'{int(sig_size)} B',
        f'{int(keygen_calls)} (~{keygen_time:.2f} s)',
        f'{int(sign_calls)} (~{sign_time:.2f} s)',
        f'{int(client_state)} B',
        f'{int(server_state)} B',
    )

def hybrid():
    sigs = '1/∞'
    # +1 for public key, +1 for bitmask seed
    sig_size = (L + 1 + 1) * N
    keygen_calls = L * W
    keygen_time = keygen_calls / SHA256_HASHRATE
    sign_calls = L * (W / 2)
    sign_time = sign_calls / SHA256_HASHRATE
    client_state = N + N
    server_state = N + FALCON_PK_SIZE
    return (
        'Hybrid-WOTS-Falcon',
        sigs,
        f'{int(sig_size)}/690 B',
        f'{int(keygen_calls)} (~{keygen_time:.2f} s)',
        f'{int(sign_calls)} (~{sign_time:.2f} s)',
        f'{int(client_state)} B',
        f'{int(server_state)} B',
    )

def shallow_deep(shallow, deep):
    sigs = 2 ** shallow + 2 ** deep
    # +1 for public key, +1 for bitmask seed, +1 for new pk
    sig_size_s = (L + 1 + 1 + 1) * N
    sig_size_d = (L + 1 + 1 + deep) * N
    keygen_calls = L * W * (2 ** shallow + 2 ** deep)
    keygen_time = keygen_calls / SHA256_HASHRATE
    # Assume whole shallow subtree is cached on server
    sign_calls = L * (W / 2)
    sign_time = sign_calls / SHA256_HASHRATE
    client_state = N + N
    # 1 pk for deep subtree, cache complete shallow subtree
    server_state = N + N * (2 ** shallow)
    return (
        f'Shallow-Deep (s={shallow}, d={deep})',
        f'{int(sigs)}',
        f'{int(sig_size_s)}/{int(sig_size_d)} B',
        f'{int(keygen_calls)} (~{keygen_time:.2f} s)',
        f'{int(sign_calls)} (~{sign_time:.2f} s)',
        f'{int(client_state)} B',
        f'{int(server_state)} B',
    )

def ctss_wots(c_len, c_mul):
    """
    CTSS has the following weird property:
    - sign takes increasingly shorter time starting from KeyGen time
    - verify on the other hand takes ever longer up until the KeyGen time
    This might be bad regarding DoS, especially late in the key's lifecycle.
    Also gives a possible side-channel.
    """
    sigs = c_len * c_mul * 2
    # +1 for public key
    sig_size = (L + 1) * N + min(1, c_mul-1) * L * N
    keygen_calls = L * W * c_len * c_mul
    keygen_time = keygen_calls / SHA256_HASHRATE
    sign_calls = L * (W * c_len / 2)
    sign_time = sign_calls / SHA256_HASHRATE
    chain_pos_space = L * ceil(log2(W * c_len))
    client_state = chain_pos_space
    server_state = chain_pos_space + N
    return (
        f'CTSS (l={c_len}, m={c_mul})',
        str(int(sigs)),
        f'{int(sig_size)} B',
        f'{int(keygen_calls)} (~{keygen_time:.2f} s)',
        f'{int(sign_calls)} (~{sign_time:.2f} s)',
        f'{int(client_state)} B',
        f'{int(server_state)} B',
    )

def xcmss_wots(c_len, height, cached_layer):
    sigs = (c_len * 2 - 1) * (2 ** height)
    # +1 for public key
    sig_size = (L + 1 + height) * N
    keygen_calls = L * W * c_len * (2 ** height)
    keygen_time = keygen_calls / SHA256_HASHRATE
    sign_calls = L * (W * c_len / 2) * 2 ** (height-cached_layer)
    sign_time = sign_calls / SHA256_HASHRATE
    chain_pos_space = L * ceil(log2(W * c_len))
    cache_space = 2 ** cached_layer * N
    client_state = chain_pos_space + cache_space + N
    server_state = chain_pos_space + N
    return (
        f'XCMSS (l={c_len}, h={height}, c={cached_layer})',
        str(int(sigs)),
        f'{int(sig_size)} B',
        f'{int(keygen_calls)} (~{keygen_time:.2f} s)',
        f'{int(sign_calls)} (~{sign_time:.2f} s)',
        f'{int(client_state)} B',
        f'{int(server_state)} B',
    )

def nots():
    W = 16
    sigs = 1
    sig_size = 2 * W * N
    keygen_calls = 2 * (2 * M * 8 / log2(W) + 1) * W
    keygen_time = keygen_calls / SHA256_HASHRATE
    sign_calls = (2 * M * 8 / log2(W) + 1) * W
    sign_time = sign_calls / SHA256_HASHRATE
    client_state = N
    server_state = N
    return (
        f'NOTS',
        str(int(sigs)),
        f'{int(sig_size)} B',
        f'{int(keygen_calls)} (~{keygen_time:.2f} s)',
        f'{int(sign_calls)} (~{sign_time:.2f} s)',
        f'{int(client_state)} B',
        f'{int(server_state)} B',
    )

if __name__ == '__main__':
    console = Console()
    table = Table(show_header=True, header_style='bold cyan')
    table.add_column('Scheme')
    table.add_column('#Sigs', justify='right')
    table.add_column('Sig. size', justify='right')
    table.add_column('Keygen time', justify='right')
    table.add_column('Avg. Sign time', justify='right')
    table.add_column('State (C)', justify='right')
    table.add_column('State (S)', justify='right')

    xmss_params = [(0, 0), (7, 0), (7, 2), (7, 4), (7, 6), (7, 7)]
    for i, (h, c) in enumerate(xmss_params):
        table.add_row(*xmss_wots(h, c), end_section=(i==len(xmss_params)-1))

    table.add_row(*hybrid(), end_section=True)

    shallow_deep_params = [(0, 7), (1, 7), (2, 7), (3, 7), (4, 7), (5, 7)]
    for i, (s, d) in enumerate(shallow_deep_params):
        table.add_row(*shallow_deep(s, d), end_section=(i==len(shallow_deep_params)-1))

    ctss_params = [(128, 1), (64, 2), (32, 4), (16, 8), (8, 16), (4, 32), (2, 64)]
    for i, (l, m) in enumerate(ctss_params):
        table.add_row(*ctss_wots(l, m), end_section=(i==len(ctss_params)-1))

    xcmss_params = [(64, 1, 1), (33, 2, 2), (17, 3, 3), (9, 4, 4), (5, 5, 5),
                    (3, 6, 0), (3, 6, 6)]
    for i, (l, h, c) in enumerate(xcmss_params):
        table.add_row(*xcmss_wots(l, h, c), end_section=(i==len(xcmss_params)-1))

    table.add_row(*nots(), end_section=True)

    console.print(table)
