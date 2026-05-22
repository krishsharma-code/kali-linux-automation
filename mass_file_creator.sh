#!/bin/bash

# mass_file_creator.sh
# This script uses a loop to generate 5 blank text files for testing.

echo "Starting mass file creation..."

# A 'for' loop that runs from 1 to 5.
for i in {1..5}
do
   # Create a file named test_file_1.txt, test_file_2.txt, etc.
   FILENAME="test_file_$i.txt"
   touch "$FILENAME"
   echo "Created: $FILENAME"
done

echo "Finished creating 5 test files."
