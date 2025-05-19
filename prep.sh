#!/usr/bin/bash

./perf.sh
sudo swapoff -a
sudo insmod kern/preload_time_module.ko
