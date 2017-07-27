#include <sys/sdt.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	char* str = malloc(18);

	puts("boop\n");
	getchar();

	STAP_PROBE(hello_provider, tracepoint_nargs_0);
	STAP_PROBE1(hello_provider, tracepoint_nargs_1, 12);
	STAP_PROBE2(hello_provider, tracepoint_nargs_2, "string", str);

	return 0;
}

