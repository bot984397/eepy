#ifndef __PS_CORE_H__
#define __PS_CORE_H__

/* @file    ps_core.h
 * @author  vmx
 * @brief   main polysleep header
 */

#include <stdint.h>

void ps_setup(void);
void ps_sleep(uint32_t ms);

void *ps_get_base_addr(void);

#endif /* __PS_CORE_H__ */
