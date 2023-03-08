open String ;;

(*

open Unix ;;

let new_socket () =
    let domain   = PF_INET in
    let ntype    = SOCK_STREAM in
    let protocol = 0 in
    socket domain ntype protocol ;;

let handle : file_descr -> file_descr = fun sock -> 
    let name     = gethostname () in
    let entry    = gethostbyname name in
    let addr     = entry.h_addr_list.(0) in
    let port     = 8086 in
    bind sock (ADDR_INET(addr, port)) ;
    sock ;;

let start () =
    let s = new_socket () in
    let s = handle s in
    let s = handle s in
    print_string "from init!\n" ;;

let _ =
    start () ;;

*)

let running = ref true in
    while !running do
        print_string "Have you had enough yet? (y/n) ";
        let str = read_line () in
        if length str > 0 then
            if str.[0] = 'y' then running := false
    done;;
