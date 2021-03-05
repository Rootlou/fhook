/*
 * =====================================================================================
 *
 *       Filename:  fhook.h
 *
 *    Description: ftrace tool to create/manage kernel hooks 
 *
 *        Version:  1.0
 *        Created:  20.02.2021 21:30:39
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  rootlou
 *
 * =====================================================================================
 */

#ifndef _FHOOK_H
#define _FHOOK_H

#include <linux/ftrace.h>

/* *
 *  @name       name of the function
 *  
 *  @func       callback/modified function
 *  
 *  @orig_func  original function
 *  
 *  @address    address of the hooked function
 *
 *  @ops        frace_ops struct contains the parameters
 * */

struct ftrace_hook {
    const char* name;
    void *func;
    void *orig_func;

    unsigned long address;
    struct ftrace_ops ops;
};


// Macro to define our hook structurei
#define HOOK(_name, _function, _original) {\
    .name = (_name),\
    .function = (_function),\
    .original = (_original),\
}

// register hooks in here
extern static struct ftrace_hook hookRegistry[]; 

// resolve address from given name
int resolve_to_address(struct ftrace_hook *hook) {
    // get the address using kallsyms (list of all kernel symbols)
    // stored in /proc/kallsyms
    hook->address = kallsyms_lookup_name(hook->name);
    if(hook->address) return -ENODEV;
    
    // cast and set the orig_func to hook->address 
    *((unsigned long) hook->orig_func) = hook->address = hook->address;
    return 0;
}

// install ftrace hook by populating our ftrace_ops
// https://www.kernel.org/doc/html/v4.19/trace/ftrace-uses.html
int ftrace_inject_hook(struct ftrace_hook *hook) {
    int error;
    
    // get address of function
    error = resolve_to_address(hook);
    if(error) return error;
    
    hook->ops.func = fh_trace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    // enable function filter for address
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0 ,0);
    if(error) return error;

    error = register_ftrace_function(&hook->ops);
    if(error) {
        // turn off ftrace in case of error
        ftrace_set_filter_ip(&hook->ops, hook->address, 1 , 0);
        return error;
    }

    return 0;
}

//  remove a hook by repeating the instructions above with their 
//  corresponding counterparts
int ftrace_remove_hook(struct ftrace_hook *hook) {
    int error;

    error = unregister_ftrace_function(&hook->ops);
    if(error) return error;

    error = ftrace_set_filter_ip(&hook->ops, hook->address, 1 , 0);
    if(error) return error;
}

#endif