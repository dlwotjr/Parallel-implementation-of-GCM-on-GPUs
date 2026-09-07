# Parallel AES-GCM on GPUs

CUDA implementation accompanying the paper **“Parallel implementation of GCM on GPUs”**. The project parallelizes both AES-CTR encryption and the GHASH authentication path for high-throughput AES-GCM processing on NVIDIA GPUs.

## Highlights

- CUDA kernels for parallel AES-GCM processing
- Parallel GHASH computation for reducing GCM's serial bottleneck
- AES-128 implementations including table-based and bitsliced variants
- Benchmark-oriented execution with CUDA event timing

The paper reports more than 400 Gb/s on an NVIDIA RTX 4090. Performance depends on the GPU, CUDA version, build flags, message size, and benchmark configuration.

## Publication

Jaeseok Lee, DongCheon Kim, and Seog Chung Seo, “Parallel implementation of GCM on GPUs,” *ICT Express*, vol. 11, pp. 310–316, 2025.

- [DOI: 10.1016/j.icte.2025.01.006](https://doi.org/10.1016/j.icte.2025.01.006)
- [Article page](https://www.sciencedirect.com/science/article/pii/S2405959525000062)

## Requirements

- Linux x86-64
- NVIDIA GPU
- NVIDIA CUDA Toolkit with `nvcc`

The original experiment targeted CUDA 12.3 and compute capability 8.6. Both can be overridden at build time.

## Build and run

```bash
make CUDA_ARCH=sm_86
./aes
```

Use another installed compiler or GPU target when needed:

```bash
make NVCC=/usr/local/cuda/bin/nvcc CUDA_ARCH=sm_89
```

Clean generated files with:

```bash
make clean
```

The default benchmark allocates a large working set and uses compile-time constants in `kernel.h`. Adjust those constants before building if the available GPU memory is limited.

## Repository layout

- `kernel.cu`, `kernel.h` — AES-GCM orchestration, GHASH kernels, and benchmark driver
- `AES.cu` — table-based AES implementation
- `aes_encrypt_gpu.cu` — GPU bitsliced AES implementation
- `aes_encrypt.cu` — host bitsliced AES implementation
- `aes_keyschedule_lut.cu` — AES key schedule
- `aes.h`, `internal-aes.h`, `tables.h` — shared declarations and lookup tables

## Attribution

The bitsliced AES source files retain their original author notices and reference the fixslicing work by Alexandre Adomnicai and Thomas Peyrin ([IACR ePrint 2020/1123](https://eprint.iacr.org/2020/1123)). See the headers in those files for details.

This repository is research code intended for reproducibility and performance evaluation. It has not been audited for production cryptographic use.
