/*
 *    Copyright (c) 2019 - 2020, Thales DIS Singapore, Inc
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 */

#include "LSerial.h"
#include <cstdio>
#include <cstring>

#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include "common.h"

//#define SERIAL_DEBUG

LSerial::LSerial(void) {
	m_uart = -1;
}

LSerial::~LSerial(void) {
}


bool LSerial::start(const char *modem_port) {
	_log( PY_LOG_LEVEL_DEBUG, "Opening serial port...");

	const char* uart = (const char*) modem_port; //"/dev/ttyACM0";
	int port;
	struct termios serial;

	if((m_uart = open(uart, O_RDWR | O_NOCTTY | O_NDELAY)) >= 0) {
		tcgetattr(m_uart, &serial);

		serial.c_iflag = 0;
		serial.c_oflag = 0;
		serial.c_lflag = 0;
		serial.c_cflag = 0;

		serial.c_cc[VMIN] = 0;
		serial.c_cc[VTIME] = 0;

		serial.c_cflag = B115200 | CS8 | CREAD;

		tcsetattr(m_uart, TCSANOW, &serial); // Apply configuration
		fcntl(m_uart, F_SETFL, 0);

		_log( PY_LOG_LEVEL_DEBUG, "Found serial %s %d\r\n", uart, m_uart);
		return true;
	}
	
	return false;
}

bool LSerial::send(char* data, unsigned long int toWrite, unsigned long  int* size) {
	unsigned long int i;
	int w;
	
	if(m_uart < 0) {
		return false;
	}
	
	for(i=0; i<toWrite;) {
		w = write(m_uart, &data[i], (toWrite - i));
		if(w == -1) {
			return false;
		}
		else if(w) {
			i += w;
		}
		
	}

	*size = toWrite;

	
	#ifdef SERIAL_DEBUG
	if(*size) {
		unsigned long int i;
		printf("> ");
		for(i=0; i<*size; i++) {
			if((data[i] != '\r') && (data[i] != '\n')) {
				printf("%c", data[i]);
			}
		}
		printf("\n");

	}
	#endif
	
	return true;
}

bool LSerial::recv(char* data, unsigned long int toRead, unsigned long int* size) {
	unsigned long int i;
	int r;
	
	if(m_uart < 0) {
		return false;
	}

    int j = 0;
    int MAX_NBR_ITER = 100; // Arbitrarily chosen value
	for(i=0; i<toRead;) {
		r = read(m_uart, &data[i], (toRead - i));
		if(r == -1) {
			return false;
		}
		else if(r) {
			i += r;
		} else if(r == 0) {
            j++;
        }
        if( j >= MAX_NBR_ITER ) {
            return false;
        }
	}

	*size = toRead;

	
	#ifdef SERIAL_DEBUG
	if(*size) {
		unsigned long int i;
		printf("< ");
		for(i=0; i<*size; i++) {
			if((data[i] != '\r') && (data[i] != '\n')) {
				printf("%c", data[i]);
			}
		}
		printf("\n");
	}
	#endif
	
	return true;
}

bool LSerial::stop(void) {
	_log( PY_LOG_LEVEL_DEBUG, "Closing serial port...");
	if(m_uart >= 0) {
		close(m_uart);
	}
	_log( PY_LOG_LEVEL_DEBUG, "OK\n");
	return true;
}

