fun pass id = return <xml><head><title>success!</title></head><body>
  welcome, {[id]}!
</body></xml>


fun fail () = return <xml><head><title>oops!</title></head><body>
  oops!
</body></xml>

fun register r =
    id <- Urauth.add_user r.UserName r.Password;
    case id of
	Some id => (redirect (url (pass id)))
      | None => (redirect (url (fail ())))
		
fun auth r =
    user_id' <- Urauth.auth_user r.UserName r.Password;
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
