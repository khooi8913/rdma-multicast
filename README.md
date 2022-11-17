# One-sided RDMA Multicast

This repository holds the Tofino prototype implementation to perform one-sided RDMA multicast, proposed in the [paper](https://dl.acm.org/doi/abs/10.1145/3493425.3502766), `Towards a Framework for One-sided RDMA Multicast` accepted at the EuroP4'21 Workshop and published at ANCS'21.

## Usage

Please find the P4 implementation `p4/rdma_icrc`.

You may need to tweak the helper scripts and environment setup w.r.t. to your environment.

Under `src/`, the client-server program can be modified to generated one-sided RDMA Write requests.


## Citation
If you find this work useful for your research, please cite:
```
@inproceedings{10.1145/3493425.3502766,
author = {Khooi, Xin Zhe and Song, Cha Hwan and Chan, Mun Choon},
title = {Towards a Framework for One-Sided RDMA Multicast},
year = {2022},
booktitle = {Proceedings of the Symposium on Architectures for Networking and Communications Systems},
pages = {129–132},
numpages = {4}
}
```

## Others

The RDMA iCRC computation is referred from this [repository](https://github.com/rutgerbeltman/telemetry-rdma-p4-switch/).

## Feedback/ Questions
We welcome questions/ comments/ feedback/ collaborations.

Please do not hesitate reach out the authors via email.

## License
Copyright 2021 Xin Zhe Khooi, National University of Singapore.

The project's source code are released here under the [MIT License](https://opensource.org/licenses/MIT).


