#!/bin/bash

# Don't run this without a make!
sudo ../iolatency 3 > latency_results.txt &
latency_pid=$!

sudo ./reference.sh 3 > reference_results.txt &
reference_pid=$!

fio test.fio

sleep 15

sleep 5

kill -SIGINT $latency_pid
kill -SIGINT $reference_pid

wait $latency_pid
wait $reference_pid

echo "done"
