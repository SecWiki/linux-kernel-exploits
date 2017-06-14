/* Copyright 2016 Google Inc
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <err.h>
#include <stdio.h>
#include <string.h>

int
main(void)
{
	struct addrinfo hints, *res;
	int r;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;

	if ((r = getaddrinfo("foo.bar.google.com", "22",
	    &hints, &res)) != 0)
		errx(1, "getaddrinfo: %s", gai_strerror(r));

	return 0;
}
