open Unix ;;

(* (fd, closed?) *)
type connection = file_descr * bool ;;

let new_server : unit -> connection = fun () ->
    let domain   = PF_INET in
    let ntype    = SOCK_STREAM in
    let protocol = 0 in
    (socket domain ntype protocol, true) ;;

let connect : connection -> connection = fun (sock, connected) ->
    let name     = gethostname () in
    let entry    = gethostbyname name in
    let addr     = entry.h_addr_list.(0) in
    let port     = 8086 in
    bind sock (ADDR_INET(addr, port)) ;
    (sock, connected) ;;

(*

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
        if String.length str > 0 && str.[0] = 'y'
            then running := false
    done;;
