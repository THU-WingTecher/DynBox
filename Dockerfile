FROM ubuntu:20.04

ENV ROOT /DynBox

COPY DynBox $ROOT

RUN apt-get update

RUN DEBIAN_FRONTEND="noninteractive" apt-get install -y python3.8 vim pip

RUN pip install openpyxl numpy
# libedit-dev libncurses5-dev python-dev cmake build-essential libncurses5-dev python-dev cmake git vim python3
# Clone the repo
WORKDIR $ROOT 

CMD /bin/bash




# Build SVF
# ENV LLVM_DIR=$ROOT/llvm/llvm-12/bin
# ENV PATH=$LLVM_DIR/:$PATH

# WORKDIR $ROOT/$GIT_REPO/SVF
# RUN ./build.sh
# WORKDIR $ROOT/$GIT_REPO/SVF/Release-build
# RUN cp $ROOT/$GIT_REPO/SVF/Release-build/bin/* /usr/bin/