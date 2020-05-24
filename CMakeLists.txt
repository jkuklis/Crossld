cmake_minimum_required (VERSION 3.5)

enable_language(C ASM)

project (crossld C ASM)

set(ZAD1_SRC src/crossld.h src/crossld.c src/common.h src/common.c
        src/preparation.c src/preparation.h src/loader.c src/loader.h src/asm.h src/called_invoker.c src/called_invoker.h)
add_library(crossld SHARED ${ZAD1_SRC})

set_target_properties(crossld PROPERTIES C_VISIBILITY_PRESET hidden)

set_target_properties(crossld PROPERTIES LINKER_LANGUAGE C)
