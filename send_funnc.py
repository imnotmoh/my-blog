def send(mail, password, receive_addrs, message):
    import smtplib
    with smtplib.SMTP("smtp.gmail.com", port=587) as server:
        server.starttls()
        server.login(user=mail, password=password)
        server.sendmail(
            from_addr=mail,
            to_addrs=receive_addrs,
            msg=message
         )
