from flask import render_template

@app.route("/", methods=["GET", "POST"])
def splash():
    original_url = request.args.get("url", "")
    if request.method == "POST":
        # Process the form data and redirect
        # Assuming form handling code here
        return redirect(generate_redirect_url())
    else:
        return render_template("splash.html", splash_header="Welcome!", original_url=original_url)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        # Process the admin form data
        pass
    total_registrations = get_total_registrations()
    return render_template("admin.html", device_name="Howzit Device", total_registrations=total_registrations)
