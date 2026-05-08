#!/usr/bin/env bash
apt-get update && apt-get install -y g++
g++ -O2 -std=c++17 -o cipher cipher.cpp
pip install -r requirements.txt
