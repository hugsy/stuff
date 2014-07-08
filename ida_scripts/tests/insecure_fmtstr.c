#include <stdio.h>

void secure_format_string(char* msg){
	printf("%s\n", msg);
}

void insecure_format_string(char* msg){
	printf(msg);
}

int main(int argc, char** argv, char** envp){
	secure_format_string(argv[1]);
	insecure_format_string(argv[1]);
	return 0;
}
