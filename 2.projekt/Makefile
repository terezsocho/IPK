# build an executable named ipk-sniffer from ipk-sniffer.cpp
FILE=ipk-sniffer
CC=g++
FLAGS=-g -Wall -Werror -pedantic -std=c++11
all:
	$(CC) $(FLAGS) ipk-parser.cpp ipk-sniffer.cpp -o $(FILE) -lpcap 