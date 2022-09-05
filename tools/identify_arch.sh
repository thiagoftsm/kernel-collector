#!/bin/bash

print_arch() {
    # Options from https://stackoverflow.com/questions/45125516/possible-values-for-uname-m
    ARCH=$(uname -m)
    if [ "${ARCH}" == "x86_64" ]; then
        echo "x86"
    elif [ "${ARCH}" == "i386" ]; then
        echo "x86"
    elif [ "${ARCH}" == "i686" ]; then
        echo "x86"
    elif [ "${ARCH}" == "armv7l" ]; then
        echo "arm"
    elif [ "${ARCH}" == "armv8b" ]; then
        echo "arm"
    elif [ "${ARCH}" == "armv8l" ]; then
        echo "arm"
    fi
}

print_arch
