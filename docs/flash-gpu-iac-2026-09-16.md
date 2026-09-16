# Flash GPU自動構成

2026-09-16 UTC。Terraformの `gpu_host_configuration` は、通常Podを実行できる管理対象ノードを
Ansibleで検査する。Ubuntu 24.04以降のamd64、NVIDIA display/3D controller、Ubuntuが
`nvidia-driver-580` を推奨することを同時に満たしたノードだけをGPU対応にする。
`uc-k8sp5` はGTX 1080 Ti 2基を宣言値として照合する。`uc-k8sp4` のGT 710はUbuntuの
推奨ドライバが470で、CUDA 12用のこの実行環境を満たさないため対象外になる。
専用マスター3台は候補に含めず、引き続き通常Podを配置しない。

対応ホストには580.178.04ドライバとNVIDIA Container Toolkit 1.20.0を固定し、nouveauからの
切替時だけcordon、Pod退避、再起動、uncordonを行う。`nvidia-smi`で物理GPU数を確認した後に
ハードウェア検証済みラベルを付ける。Terraformが作るArgo CD Applicationは、`nvidia`
RuntimeClassとNVIDIA device plugin 0.20.0を管理する。共有設定は有効にしない。

`gpu_acceptance` はKubernetesのallocatable GPU数と物理宣言値を照合し、digest固定のCUDA
コンテナを各GPUノードで起動する。Podはrequestとlimitをともに `nvidia.com/gpu: 1` とし、
コンテナ内で見えるGPUが厳密に1基であることを確認する。全ノードで成功した後だけ
`flash.heterocloud.io/gpu-ready=true` を付ける。FlashのGPU Podはこのラベルを要求するため、
未検証ノードには配置されない。

Flash APIの `gpu_count` は省略時0、最大1である。0は従来のgVisor、1はNVIDIAランタイムを
使う。GPU Deploymentは更新時の余分なGPUを要求しないよう `maxSurge: 0` とする。
