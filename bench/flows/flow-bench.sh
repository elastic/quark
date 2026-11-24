#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Elastic NV
#
# Measure what quark's flow accounting costs
#
# Requirements: awk, coreutils, findutils, root, Linux 5.8, two cpus or more
#               and an otherwise idle machine. Run make first.
#
# Usage:
#
#   ./flow-bench.sh [-d addr] [-i ifname] [-r reps] udp [flows|pps]
#
#   The CPU cost lands in two places, each driven by a different property
#   of the traffic, so there are two benchmarks. Both run unless one is selected.
#
#   flows  The userspace library cost, bounded by how many distinct flows there
#          are in one aggregation period, since each one is drained from the
#          kernel and becomes an event. We offer N flows per period at one
#          packet each and measure the CPU time of a process that takes every
#          event and discards it (with-quark).
#
#   pps    The kernel cost, bounded by how many packets there are, since
#          each one runs our programs in the context of whoever sends it. That
#          never shows as quark's own CPU time, so we keep some senders busy
#          and have the kernel time our programs, with the feature off and on.
#
#   pps is compared against a baseline that already attaches the same
#   programs, so its figures are the cost of the accounting alone. Results are
#   markdown on stdout, progress goes to stderr.
#
# Examples:
#
#   Both benchmarks over loopback, about 5 minutes:
#
#     ./flow-bench.sh udp
#
#   A rough answer, quickly:
#
#     ./flow-bench.sh -r 1 udp pps
#
#   Across a real device. Quark and the senders run here, nothing has to run
#   on the other machine:
#
#     ./flow-bench.sh -d 10.0.0.2 -i eth0 udp
#
#   The destination should be a machine we control:
#     - flows sends a datagram to one UDP port for each flow, from 1024 up,
#       every period.
#     - pps sends to port 22000 as fast as it can.
#
# Adding a protocol:
#
#   Write its proto_ function below, and a loader that takes the flows and pps
#   commands of udp-load.

set -e

# A failure inside $(...) stops us there too
shopt -s inherit_errexit

# Our numbers have a decimal point. printf, awk and sort go by the locale,
# and a locale that writes a comma there introduces parsing errors.
export LC_ALL=C

#
# Configuration
#

# Where the traffic goes (-d)
: "${ADDR:=127.0.0.1}"

# Device the traffic leaves through, optional (-i)
: "${IFACE:=}"

# Runs behind each figure (-r)
: "${REPS:=3}"

# Senders in the threaded pps run. One sender already tells what a packet
# costs, the threaded run only checks that it holds with several CPUs in the
# programs at once. A few are enough for that and more only fight over the
# device, so the default is 4, or what is left: with-quark sits on CPU 0 and
# each sender on a CPU of its own from 1 up.
: "${THREADS:=$(( $(nproc) > 4 ? 4 : $(nproc) - 1 ))}"

# Aggregation period we ask of quark, in ms
period=3000

# Flows the kernel holds per period. We set it instead of taking quark's
# default so that the maximum number of flows we use in the benchmark fits.
max_flows=65536

# flows: periods we measure
measured=4

# pps: seconds each run sends for
seconds=5

# pps: packet rate at which we state the cost
rate=100000

dir="$(dirname "$0")"

#
# Protocols
#
# Each names its loader, two sets of with-quark flags (the baseline, and the
# baseline plus the feature we are measuring) and the BPF programs a packet
# runs.
#

function proto_udp {
  load="${dir}/udp-load"
  base_name='QQ_DNS'
  base_flags=(-N)
  flow_name='QQ_UDP_FLOW'
  flow_flags=(-N -U -A "${period}" -f "${max_flows}")
  flow_points=(1024 8192 32768 61440)
  packet_progs=(skb_egress skb_ingress)
}

#
# Functions
#

function usage {
  echo "Usage: $0 [-d addr] [-i ifname] [-r reps] udp [flows|pps]"
  echo
  echo "Benchmarks (default: both):"
  echo
  echo "  flows       Userspace library time and (kernel CPU time per flow), by flows"
  echo "              per aggregation period"
  echo "  pps         Kernel CPU time, per packet"
  echo
  echo "Options, with the environment variable each one defaults to:"
  echo
  echo "  -d addr     Where the traffic goes (ADDR, default: ${ADDR})"
  echo "  -i ifname   Device the traffic leaves through (IFACE, default: let routing decide)"
  echo "  -r reps     Runs behind each figure (REPS, default: ${REPS})"
  echo
  echo "Environment:"
  echo
  echo "  THREADS     Senders in the threaded pps run (default: ${THREADS})"
  echo
  echo "The destination gets a datagram on each UDP port from 1024 up, one per"
  echo "flow, and as many as we can send on port 22000: ensure it's a machine we control."
  echo
  exit 1
}

function __progress {
  printf '[*] %s\n' "$*" >&2
}

# Pick the value of a name from "name value" lines.
function __val {
  awk -v name="$1" '$1 == name { print $2 }'
}

# The parentheses matter: awk takes a bare > in printf for a redirection.
function __calc {
  awk "BEGIN { printf \"%.3f\", ($1) }"
}

# Median of a list of numbers, and half their range in percent of it.
function __median {
  xargs -n 1 <<< "$1" |
    sort -n |
    awk '{ v[NR] = $1 }
         END {
           m = NR % 2 ? v[(NR + 1) / 2] : (v[NR / 2] + v[NR / 2 + 1]) / 2
           printf "%f %d\n", m, (m > 0 ? (v[NR] - v[1]) * 50 / m + 0.5 : 0)
         }'
}

# Run the loader with a queue open:
# __with_quark <with-quark flags> -- <loader command> [loader args].
#
# What we add goes right after the command, ahead of any operand.
# Only glibc's getopt takes options in any order, musl (e.g. alpine)
# stops at the first non-option.
function __with_quark {
  local flags=()

  while [ "$1" != '--' ]; do
    flags+=("$1")
    shift
  done
  shift

  "${dir}/../with-quark" "${flags[@]}" \
    "${load}" "$1" -d "${ADDR}" ${IFACE:+-i "${IFACE}"} "${@:2}"
}

# Time quark's packet programs took for each flow of a flows run, in ns:
# __ns_per_flow <with-quark output> <flows sent while it measured>.
#
# This is all of their time over the flows sent, not the sum of their
# averages as in __ns_per_packet. Nobody listens where the flows go, so over
# loopback the kernel answers each datagram with an ICMP error, which runs the
# egress program a second time: its average is that of two different runs.
# Whatever else the machine sends is billed to our flows too.
function __ns_per_flow {
  local out="$1" flows="$2" prog runs ns total=0

  for prog in "${packet_progs[@]}"; do
    runs="$(__val "prog_runs.${prog}" <<< "${out}")"
    ns="$(__val "prog_ns.${prog}" <<< "${out}")"
    total="$(__calc "${total} + ${runs:-0} * ${ns:-0}")"
  done
  if [ "$(__calc "${total} > 0 && ${flows} > 0")" != '1.000' ]; then
    echo "$0: the kernel timed none of ${packet_progs[*]} for the flows sent" >&2
    exit 1
  fi

  __calc "${total} / ${flows}"
}

function cmd_flows {
  local -A cpu sent kern kcpu lost
  local warmup window r n out median spread percent ns spread_ns k spread_k
  local wall flows

  # Two and a half periods of warm-up, so that the window we measure opens
  # and closes halfway between two drains.
  warmup=$((period * 5 / 2))
  window=$((measured * period))

  for ((r = 1; r <= REPS; r++)); do
    for n in "${flow_points[@]}"; do
      # The loader runs until with-quark has measured its window
      out="$(__with_quark --prog-stats "${flow_flags[@]}" \
               --warmup "${warmup}" --duration "${window}" -- \
               flows -P "${period}" "${n}")"
      percent="$(__val sent_percent <<< "${out}")"
      # with-quark measures for a little longer than told, and the kernel
      # times the programs for as long: go by the time it says it took.
      wall="$(__val wall_ms <<< "${out}")"
      flows="$(__calc "${n} * ${percent} / 100 * ${wall} / ${period}")"
      ns="$(__ns_per_flow "${out}" "${flows}")"
      cpu[$n]+=" $(__val cpu_percent <<< "${out}")"
      sent[$n]+=" ${percent}"
      kern[$n]+=" ${ns}"
      # All of the programs' time over that of the measurement, in percent
      kcpu[$n]+=" $(__calc "${ns} * ${flows} / (${wall} * 10000)")"
      lost[$n]=$((${lost[$n]:-0} + $(__val lost <<< "${out}")))
      __progress "flows ${r}/${REPS}, ${n} flows: ${percent}% sent," \
                 "${cpu[$n]##* }% cpu, ${kcpu[$n]##* }% in the kernel" \
                 "at ${ns} ns per flow, ${lost[$n]} lost so far"
    done
  done

  printf '\n### %s: cost by flows per period\n\n' "${flow_name}"
  printf '| flows per period | flows sent | quark CPU, %% of one core |'
  printf ' kernel CPU, %% of one core | kernel CPU, ns per flow | lost |\n'
  printf '|---:|---:|---:|---:|---:|---:|\n'
  for n in "${flow_points[@]}"; do
    read -r median spread < <(__median "${cpu[$n]}")
    read -r percent _ < <(__median "${sent[$n]}")
    read -r k spread_k < <(__median "${kcpu[$n]}")
    read -r ns spread_ns < <(__median "${kern[$n]}")
    printf '| %d | %.0f | %.2f +/-%d%% | %.2f +/-%d%% | %.0f +/-%d%% | %d |\n' \
           "${n}" "$(__calc "${n} * ${percent} / 100")" \
           "${median}" "${spread}" "${k}" "${spread_k}" \
           "${ns}" "${spread_ns}" "${lost[$n]}"
  done

  cat <<EOF

One packet to each flow every ${period} ms period, measured over ${measured} periods.
Flows sent is how many the loader got out per period: where that is short of
the first column the sender could not get them through the device fast
enough, and the CPU figures are those of the flows sent. Quark CPU is the time
of a process which takes every event and discards it, not that of the sender.
Kernel CPU is the sender's share: the time the programs quark attaches to the
packet path (${packet_progs[*]}) took for the flows it sent, as timed by
the kernel, first in percent of one core as for quark, then for each flow. It
is all of their time, not what ${flow_name} adds to it, and other traffic on
the machine counts too.
Lost is events dropped by the ring plus packets refused by a full flow map,
which we size for ${max_flows} flows per period whatever quark's default is.
EOF
}

# Time quark's programs take for one packet, in ns: __ns_per_packet <senders>
# <with-quark flags>. Prints that, how many programs each packet ran, the
# percentage of sends the kernel refused and how long a sender took for one
# packet in all.
#
# The timing is an average over every packet of the machine, which is why
# the machine has to be idle to avoid skewing the results.
function __ns_per_packet {
  local senders="$1" out pps packets prog runs ns=0 ran=0
  shift

  out="$(__with_quark --prog-stats "$@" -- pps -j "${senders}" -t "${seconds}")"
  pps="$(__val pps <<< "${out}")"
  if (( pps == 0 )); then
    echo "$0: the senders got no packet out" >&2
    exit 1
  fi
  packets=$((pps * seconds))
  for prog in "${packet_progs[@]}"; do
    runs="$(__val "prog_runs.${prog}" <<< "${out}")"
    if (( ${runs:-0} * 2 >= packets )); then
      ns="$(__calc "${ns} + $(__val "prog_ns.${prog}" <<< "${out}")")"
      ran=$((ran + 1))
    fi
  done
  if (( ran == 0 )); then
    echo "$0: the kernel timed none of ${packet_progs[*]} for the packets sent" >&2
    exit 1
  fi

  echo "${ns} ${ran} $(__val refused_percent <<< "${out}")" \
       "$(__calc "${senders} * 1000000000 / ${pps}")"
}

function cmd_pps {
  local -A base flow whole
  local senders=(1) r n out b f w spread_b spread_f ran refused worst=0
  local scale=1 b1 f1 how

  if (( THREADS > 1 )); then
    senders+=("${THREADS}")
  fi

  for ((r = 1; r <= REPS; r++)); do
    for n in "${senders[@]}"; do
      out="$(__ns_per_packet "${n}" "${base_flags[@]}")"
      read -r b ran refused w <<< "${out}"
      worst="$(__calc "${refused} > ${worst} ? ${refused} : ${worst}")"
      # How long a send takes only means something if few were turned away
      if (( n == 1 )) && [ "$(__calc "${refused} > 10")" = '1.000' ]; then
        scale=0
      fi
      out="$(__ns_per_packet "${n}" "${flow_flags[@]}")"
      read -r f ran refused _ <<< "${out}"
      worst="$(__calc "${refused} > ${worst} ? ${refused} : ${worst}")"
      base[$n]+=" ${b}"
      flow[$n]+=" ${f}"
      whole[$n]+=" ${w}"
      __progress "pps ${r}/${REPS}, senders ${n}: ${b} ns per packet," \
                 "${f} with ${flow_name}, up to ${worst%.*}% of sends refused so far"
    done
  done

  printf '\n### %s: cost in the kernel, CPU time per packet\n\n' "${flow_name}"
  printf '| senders | %s | with %s | added | added at %d packets/s |\n' \
         "${base_name}" "${flow_name}" "${rate}"
  printf '|---:|---:|---:|---:|---:|\n'
  for n in "${senders[@]}"; do
    read -r b spread_b < <(__median "${base[$n]}")
    read -r f spread_f < <(__median "${flow[$n]}")
    printf '| %d | %.0f ns +/-%d%% | %.0f ns +/-%d%% | %.0f ns | %.1f%% of one core |\n' \
           "${n}" "${b}" "${spread_b}" "${f}" "${spread_f}" \
           "$(__calc "${f} - ${b}")" \
           "$(__calc "(${f} - ${b}) * ${rate} / 10000000")"
    if (( n == 1 )); then
      b1="${b}"
      f1="${f}"
    fi
  done

  # The first two columns invite the reading that packets got f1/b1 times
  # slower. Say what they are and give the whole of a send for scale.
  read -r w _ < <(__median "${whole[1]}")
  if (( scale )); then
    how="$(printf 'Sending one of these packets took about %.0f ns in all here' "${w}")"
  else
    how='Sending a packet takes a microsecond or more of kernel time whatever quark does'
  fi
  echo
  printf '%s %s %s, so going from %.0f ns to %.0f ns makes a packet cost %.0f ns more, %s %s\n' \
         "How to read this: the first two columns are not what a packet costs." \
         "They are the small part of it spent in the programs quark attaches to" \
         "the packet path, as timed by the kernel, without and with ${flow_name}. ${how}" \
         "${b1}" "${f1}" "$(__calc "${f1} - ${b1}")" \
         "$(printf 'not %.1f times slower.' "$(__calc "${f1} / ${b1}")")" \
         "The added time is the figure to take away, and the last column is the CPU it comes to for a program moving ${rate} packets a second." |
    fold -s -w 78 |
    sed 's/ *$//'

  cat <<EOF

The senders put out small datagrams for ${seconds} s, each on a CPU and a connected
socket of its own. Both columns include a little of what the timing itself
costs, which cancels out in the added time. ${base_name} attaches the same
programs with the accounting off. The kernel times them for every packet on
the machine, not only for ours, so other traffic waters the figures down.
EOF
  if (( ran > 1 )); then
    echo "Each packet ran the programs twice, on its way out and on its way in," \
         "as the destination is this machine."
  else
    echo "Each packet ran the programs once, on its way out. The destination is" \
         "another machine, which is not measured."
  fi
  if [ "$(__calc "${worst} > 1")" = '1.000' ]; then
    printf 'Up to %.0f%% of the sends failed. Those never reach the ' "${worst}"
    echo "programs, so the figures stand, but something other than the CPU" \
         "held the senders back: the device queue had no room, or the" \
         "destination answered with ICMP errors."
  fi
}

#
# Argument parsing
#

while getopts 'd:i:r:' opt; do
  case "${opt}" in
    d)
      ADDR="${OPTARG}"
      ;;
    i)
      IFACE="${OPTARG}"
      ;;
    r)
      REPS="${OPTARG}"
      ;;
    *)
      usage
      ;;
  esac
done
shift $((OPTIND - 1))

if [ $# -gt 2 ]; then
  usage
fi

if ! [[ "${REPS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "Invalid number of runs: ${REPS}" >&2
  exit 1
fi

case "$1" in
  udp)
    "proto_$1"
    ;;
  ?*)
    echo "Unknown protocol: $1" >&2
    exit 1
    ;;
  *)
    usage
    ;;
esac

case "$2" in
  flows|pps)
    benchmarks=("$2")
    ;;
  ?*)
    echo "Unknown benchmark: $2" >&2
    exit 1
    ;;
  *)
    benchmarks=(flows pps)
    ;;
esac

printf '%s flows on Linux %s %s, to %s%s, median of %d runs +/- half the range\n' \
       "$1" "$(uname -r)" "$(uname -m)" "${ADDR}" "${IFACE:+ via ${IFACE}}" "${REPS}"

for benchmark in "${benchmarks[@]}"; do
  "cmd_${benchmark}"
done
