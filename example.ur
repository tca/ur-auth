structure ExAuth = Urauth.Make(struct
				   val hash_length = 20
				   val iterations = 1024
				   val session_length = 7
				   val secure_cookie = False
				   fun derive_salt i u p = i <- rand; return (show i)
			       end)

fun secret () =
    so <- ExAuth.get_session ();
    return <xml><head><title>Secret Area!</title></head><body>
      {case so of
	   None => <xml>no trespassing!</xml>
	 | Some id => <xml>welcome, {[id]}!</xml>}
    </body></xml>

fun err () =
    so <- ExAuth.get_session ();
    return <xml><head><title>error!</title></head><body>
      error!
    </body></xml>
				 
fun register r =
    r <- ExAuth.add_user r.UserName r.Password;
    case r of
	None => redirect (url (err ()))
      | _ => redirect (url (secret ()))
	      
fun auth r =
    r <- ExAuth.auth_user r.UserName r.Password;
    case r of
	None => redirect (url (err ()))
      | _ => redirect (url (secret ()))

fun forms () = <xml>
  <h1>Register</h1>
  <form>
    <textbox{#UserName}/>
    <textbox{#Password}/>
    <submit action={register} value="Register"/>
  </form>
  <h1>Login</h1>
  <form>
    <textbox{#UserName}/>
    <textbox{#Password}/>
    <submit action={auth} value="Login"/>
  </form>
</xml>

fun main () =
    so <- ExAuth.get_session ();
    case so of
	Some _ => (redirect (url (secret ())))
      | None => 
	return <xml><head><title>Ur/Web Auth Example</title></head><body>
	  {forms ()}
	</body></xml>
