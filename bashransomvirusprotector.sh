#!/bin/bash
# -------------------------------------------------------------------------------------------
#
# BashRansomVirusProtector.sh
#
# by Marco Marcoaldi @ Managed Server S.r.l. info@managedserver.it
#
# This is a Pure Bash adaptation of the Original Idea and Python3 code
# by Giovambattista Vieri titled "RansomVirusProtector".
#
# Source: https://github.com/gvieri/ransomvirusprotector
#
#
# Introduction Quoted by Giovambattista:
#
# " We live in tragic times where war is returning in Europe. After experiencing
# death and destructions in various parts of the world, we now face the challenge
# of cyberwarfare and rogue cyber attacks. While I cannot stop a cyber war, I hope
# this script will become useful to SME's owners and healthcare organizations.
# In essence, malware needs to "phone home" for both activation and to exfiltrate
# stolen data. It phones home to get the 'key' to encrypt all your data before
# asking for ransom.
#
# What if it can't "phone home"? Nothing... It will wait and will try to communicate
# with its owner by using other means. But a correctly configured firewall can buy
# you some time to fix the thing.
#
# Therefore, I have written and published this script that I use as a sort of
# "Swiss knife" to block suspect IPs coming from a given country or, a set of countries...
#
# I'm using it on Linux, but it can be used on Windows too. You can try on WSL
# (Linux on Windows) and maybe from PowerShell.
#
# The license? AGPL. Look at it. "
#
# Examples of use and Syntax:
#
# Obtain net blocks related to France:
# ./bashransomvirusprotector.sh -c FR
#
# Net blocks related to Italy and France:
# ./bashransomvirusprotector.sh -c FR,IT
#
# To block all Russian IP addresses:
# ./bashransomvirusprotector.sh -c RU -p "iptables -I INPUT -s " -P " -j REJECT"
#
# Then, to block all connections coming from Russia and generate an iptables script:
# ./bashransomvirusprotector.sh -c RU -p "iptables -I INPUT -s " -P " -j REJECT" > script.sh
#
# This will produce a script to block all connections coming from Russia.
#
# --------------------------------------------------------------------------------------------

# Initial setup
fn='delegated-ripencc-latest'
md5fn='delegated-ripencc-latest.md5'
site="https://ftp.ripe.net/pub/stats/ripencc/"
verbose=0
headerfilename=""
prefix=""
postfix=""
countrieslist=""

checkInstalledCommands() {
    local missing_commands=()
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || missing_commands+=("$cmd")
    done
    if [ ${#missing_commands[@]} -ne 0 ]; then
        echo "The following commands are required but not installed: ${missing_commands[*]}. Aborting."
        exit 1
    fi
}

checkInstalledCommands curl md5sum awk

# Show usage if no arguments
if [ $# -eq 0 ]; then
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -H, --header       Header file name to prepend to output"
    echo "  -p, --prefix       Prefix for each line of output"
    echo "  -c, --countries    Country codes, comma-separated (e.g., 'RU,IT')"
    echo "  -P, --postfix      Postfix for each line of output"
    echo "  -v, --verbose      Enable verbose output"
    exit 1
fi

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
    -H | --header)
        headerfilename="$2"
        shift 2
        ;;
    -p | --prefix)
        prefix="$2"
        shift 2
        ;;
    -c | --countries)
        countrieslist="$2"
        shift 2
        ;;
    -P | --postfix)
        postfix="$2"
        shift 2
        ;;
    -v | --verbose)
        verbose=1
        shift
        ;;
    *)
        echo "Unknown option: $1"
        exit 1
        ;;
    esac
done

# Check if countrieslist is empty
if [ -z "$countrieslist" ]; then
    echo "No countries specified. Please provide country codes."
    exit 1
fi

# Function to download files
download() {
    curl -s "$1$2" -o "$2"
    if [ $? -ne 0 ]; then
        echo "Error downloading $2"
        exit 1
    fi
}

# Function to verify MD5
verifyFileMd5() {
    local original_md5 computed_md5
    original_md5=$(awk '/MD5/ {print $NF}' "$2")
    computed_md5=$(md5sum "$1" | awk '{print $1}')
    if [ "$original_md5" == "$computed_md5" ]; then
        [ $verbose -eq 1 ] && echo "MD5 verified successfully."
        return 0
    else
        echo "MD5 verification failed!"
        return 1
    fi
}

# Download and verify files
download "$site" "$fn"
download "$site" "$md5fn"
if ! verifyFileMd5 "$fn" "$md5fn"; then
    echo "MD5 verification failed for $fn. Exiting."
    exit 1
fi

# Function to calculate CIDR (fast)
calculate_cidr() {
    local num_hosts=$1

    if [ "$num_hosts" -le 1 ]; then
        echo 32
    elif [ "$num_hosts" -le 2 ]; then
        echo 31
    elif [ "$num_hosts" -le 4 ]; then
        echo 30
    elif [ "$num_hosts" -le 8 ]; then
        echo 29
    elif [ "$num_hosts" -le 16 ]; then
        echo 28
    elif [ "$num_hosts" -le 32 ]; then
        echo 27
    elif [ "$num_hosts" -le 64 ]; then
        echo 26
    elif [ "$num_hosts" -le 128 ]; then
        echo 25
    elif [ "$num_hosts" -le 256 ]; then
        echo 24
    elif [ "$num_hosts" -le 512 ]; then
        echo 23
    elif [ "$num_hosts" -le 1024 ]; then
        echo 22
    elif [ "$num_hosts" -le 2048 ]; then
        echo 21
    elif [ "$num_hosts" -le 4096 ]; then
        echo 20
    elif [ "$num_hosts" -le 8192 ]; then
        echo 19
    elif [ "$num_hosts" -le 16384 ]; then
        echo 18
    elif [ "$num_hosts" -le 32768 ]; then
        echo 17
    elif [ "$num_hosts" -le 65536 ]; then
        echo 16
    elif [ "$num_hosts" -le 131072 ]; then
        echo 15
    elif [ "$num_hosts" -le 262144 ]; then
        echo 14
    elif [ "$num_hosts" -le 524288 ]; then
        echo 13
    elif [ "$num_hosts" -le 1048576 ]; then
        echo 12
    elif [ "$num_hosts" -le 2097152 ]; then
        echo 11
    elif [ "$num_hosts" -le 4194304 ]; then
        echo 10
    elif [ "$num_hosts" -le 8388608 ]; then
        echo 9
    elif [ "$num_hosts" -le 16777216 ]; then
        echo 8
    elif [ "$num_hosts" -le 33554432 ]; then
        echo 7
    elif [ "$num_hosts" -le 67108864 ]; then
        echo 6
    elif [ "$num_hosts" -le 134217728 ]; then
        echo 5
    elif [ "$num_hosts" -le 268435456 ]; then
        echo 4
    elif [ "$num_hosts" -le 536870912 ]; then
        echo 3
    elif [ "$num_hosts" -le 1073741824 ]; then
        echo 2
    else
        echo 1
    fi
}

# Process and print addresses
processAddresses() {
    local -a country_codes
    local line net num_hosts cidr_bits
    IFS=',' read -ra country_codes <<<"$countrieslist"

    while IFS='|' read -ra line; do
        if [[ "${line[2]}" == "ipv4" ]] && [[ " ${country_codes[*]} " == *" ${line[1]} "* ]]; then
            net="${line[3]}"
            num_hosts="${line[4]}"
            cidr_bits=$(calculate_cidr "$num_hosts")
            echo "${prefix}${net}/${cidr_bits}${postfix}"
        fi
    done <"$fn"
}

# Print header if specified
if [ -n "$headerfilename" ]; then
    cat "$headerfilename"
fi

processAddresses
