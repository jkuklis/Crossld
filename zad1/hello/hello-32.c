asm (
	".global _start\n"
	"_start:\n"
    "ret;\n"
	"call hello;\n"
	"hlt;\n"
);

//_Noreturn
void exit_(int status);
void print(char *str);

void hello()
{
	print("Hello world\n");
	exit_(0);
}