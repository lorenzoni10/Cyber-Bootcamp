#!/bin/bash
sudo stress --cpu  8 --vm 1 --io 3 --vm-bytes 256 2> /dev/null &
