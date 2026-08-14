#include <stdio.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

int main(void) {
  unsigned char buffer[256];
  size_t count;
#ifdef _WIN32
  (void)_setmode(_fileno(stdin), _O_BINARY);
  (void)_setmode(_fileno(stdout), _O_BINARY);
#endif
  while ((count = fread(buffer, 1u, sizeof(buffer), stdin)) != 0u) {
    if (fwrite(buffer, 1u, count, stdout) != count) return 2;
  }
  if (ferror(stdin) ||
      fwrite("native-stderr", 1u, sizeof("native-stderr") - 1u, stderr) !=
          sizeof("native-stderr") - 1u ||
      fflush(stdout) != 0 || fflush(stderr) != 0)
    return 3;
  return 0;
}
