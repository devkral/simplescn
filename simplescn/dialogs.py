
import logging
from simplescn import classify_local, classify_redirect, pwcallmethod, notify, check_argsdeco, logcheck


class client_dialogs(object):
    validactions_dialogs={"open_pwrequest", "open_notify"}
    
    @check_argsdeco({"message": str}, optional={"requester": str})
    @classify_local
    @classify_redirect
    def open_pwrequest(self, obdict):
        """ func: open password dialog
            return: pw or None, or error when not allowed
            message: message for the password dialog
            requester: plugin calling the password dialog (default: ""=main application) """
        if obdict.get("clientcerthash") is None or self.receive_redirect_hash == "" or self.receive_redirect_hash != obdict.get("clientcerthash"):
            return False, "auth failed"
        temp = pwcallmethod(obdict.get("message"), obdict.get("requester", ""))
        return True, {"pw": temp}

    @check_argsdeco({"message": str}, optional={"requester": str})
    @classify_local
    @classify_redirect
    def open_notify(self, obdict):
        """ func: open notification dialog
            return: True or False, or error when not allowed
            message: message for the notification dialog
            requester: plugin calling the notification dialog (default: ""=main application) """
        if obdict.get("clientcerthash","") == "" or self.receive_redirect_hash == "" or self.receive_redirect_hash != obdict.get("clientcerthash",""):
            return False, "auth failed"
        temp = notify(obdict.get("message"), obdict.get("requester", ""))
        return True, {"result": temp}
        
    # internal method automatically redirecting
    def use_pwrequest(self, message, requester=""):
        if self.redirect_addr == "" or self.redirect_hash == "":
            return pwcallmethod(message, requester)
        else:
            try:
                resp = self.do_request(self.redirect_addr, "/client/open_pwrequest",body={"message": message, "requester":requester}, forcehash=self.redirect_hash, sendclientcert=True, forceport=True)
            except Exception as e:
                logging.error(e)
                return None
            if logcheck(resp, logging.ERROR) == False:
                return None
            return resp[1].get("pw")
        
    # internal method automatically redirecting
    def use_notify(self, message, requester=""):
        if self.redirect_addr == "" or self.redirect_hash == "":
            return pwcallmethod(message, requester)
        else:
            try:
                resp = self.do_request(self.redirect_addr, "/client/open_notify",body={"message": message, "requester":requester}, forcehash=self.redirect_hash, sendclientcert=True, forceport=True)
            except Exception as e:
                logging.error(e)
                return None
            if logcheck(resp, logging.ERROR) == False:
                return None
            return resp[1].get("result")
    
    # remove and implement in open_pwrequest???
    def pw_auth(self, hashpcert, reqob, reauthcount):
        authob = None
        if reauthcount == 0:
            authob = self.links["auth_client"].reauth(hashpcert, reqob, hashpcert)
        if authob is None and reauthcount <= 3:
            if reqob.get("realm") is not None:
                self.links["auth_client"].delauth(hashpcert, reqob["realm"])
            authob = self.links["auth_client"].auth(self.use_pwrequest("Please enter password for {}".format(reqob["realm"])), reqob, hashpcert, hashpcert)
        return authob

