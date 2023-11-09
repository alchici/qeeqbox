#!/bin/bash

# Generate a random number between 1 and 100
random_number=$((1 + RANDOM % 100))

# Print the random number
echo "Random Number: $random_number"
