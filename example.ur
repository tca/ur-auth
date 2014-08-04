fun pass id = return <xml><head><title>success!</title></head><body>
  welcome, {[id]}!
</body></xml>


fun fail () = return <xml><head><title>oops!</title></head><body>
  oops!
</body></xml>

structure ExAuth = Urauth.Make(struct
				   val hash_length = 20
				   val iterations = 1024
				   fun derive_salt i u p = i <- rand; return (show i)
			       end)

fun register r =
    id <- ExAuth.add_user r.UserName r.Password;
    case id of
	Some id => (redirect (url (pass id)))
      | None => (redirect (url (fail ())))
		
fun auth r =
    user_id' <- ExAuth.auth_user r.UserName r.Password;
    case user_id' of
	None => (redirect (url (fail ())))
      | Some user_id => (redirect (url (pass user_id)))

fun main i =
    return <xml><head><title>asd</title></head><body>
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
    </body></xml>
