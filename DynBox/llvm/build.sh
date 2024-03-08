UbuntuLLVM="https://github.com/llvm/llvm-project/releases/download/llvmorg-12.0.1/clang+llvm-12.0.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz"

wget -c "$UbuntuLLVM" -O llvm-12.0.1.tar.xz
mkdir -p llvm-12 && tar -xf llvm-12.0.1.tar.xz -C llvm-12 --strip-components 1
