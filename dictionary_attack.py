import os
import hashlib
import time



class SecurityAccountManager():
    """Compromised Security Account Manager that contains information on 
    hashed_passwords, salt used, and number of iterations"""

    def __init__(self):
        self.read_file()

    def read_file(self):
        f = open("passwords.txt", "r")
        self.salt = os.urandom(32)
        self.iterations = 1
        all_passwords = SecurityAccountManager.process_password_input(
            SecurityAccountManager.read_all_input(f), self.salt, self.iterations)
        self.passwords = all_passwords

    @staticmethod
    def process_password_input(raw_input, salt, iterations):
        all_passwords = []
        for input in raw_input:
            count = int(input[0])
            raw_password = input[2:]
            all_passwords.append(
                Password(raw_password, count, salt, iterations))
        return all_passwords

    @staticmethod
    def read_all_input(file):
        all_inputs = []
        while True:
            try:
                c_input = file.readline().rstrip().lstrip()
                if c_input.strip() != '':
                    all_inputs.append(c_input)
                else:
                    break
            except ValueError:
                print("Invalid Input")
        return all_inputs


class Password():
    def __init__(self, password, count, salt, iterations):
        self.salt = salt  # Random salt that is appended to end of raw_password
        self.iterations = iterations
        self.hashed_key = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), self.salt, self.iterations)
        self.count = count  # Number of compromised accounts that share this password


class OfflineDictionaryAttack():
    def __init__(self, security_account_manager):
        """Attacker only has access to salt, iterations, 
        encryption method, and hashed key of passwords."""
        self.num_found_passwords = 0
        self.found_passwords = set()
        self.total_passwords_checked = 0
        self.total_passwords = sum(
            [password.count for password in security_account_manager.passwords])

        # "Stolen" information from account manager
        self.hash_keys = {
            password.hashed_key: password for password in security_account_manager.passwords}
        self.salt = security_account_manager.salt
        self.iterations = security_account_manager.iterations

        # Generate list of candidate passwords
        self.most_common_password_list = [
            password for password in OfflineDictionaryAttack.read_file("most_common_passwords.txt")]
        self.all_english_words = [
            word for word in OfflineDictionaryAttack.read_file("english_words.txt")]
        self.modified_common_passwords = self.generate_more_candidate_passwords(self.most_common_password_list)
        self.modified_english_words = self.generate_more_candidate_passwords(
            self.all_english_words)

        start_time = time.time()
        self.dictionary_attack()
        print("--- %s seconds ---" % (time.time() - start_time))

    def generate_more_candidate_passwords(self, candidate_passwords):
        generated_passwords = set(candidate_passwords.copy())
        for password in candidate_passwords:
            generated_passwords.update(
                self.add_pre_suf_to_candidate_password(password))
        return generated_passwords

    def add_pre_suf_to_candidate_password(self, password):
        modified_passwords = set()
        prefixes = [chr(x) for x in range(ord('!'), ord('z') + 1)]
        for prefix in prefixes:
            modified_passwords.add(prefix + password)
            modified_passwords.add(password + prefix)
        return modified_passwords

    def dictionary_attack(self):
        """First tries 10000 most common passwords list,
        then common english words
        then several different iterations of those passwords, 
        such as adding additional characters or prefixes"""
        self.attempt_to_match_passwords(self.most_common_password_list)
        self.attempt_to_match_passwords(self.all_english_words)
        self.attempt_to_match_passwords(self.modified_english_words)
        self.attempt_to_match_passwords(self.modified_common_passwords)
        print("Found: ", self.num_found_passwords,
              " of ", self.total_passwords)
        print ("Tested: ", self.total_passwords_checked)

    def attempt_to_match_passwords(self, candidate_password_list, check_reversed=True):
        """Checks the set of hashed passwords against a candidate password list, 
        can optionally checked reversed passwords in candidate list"""
        self.total_passwords_checked += len(candidate_password_list) * (2 if check_reversed else 1) 
        for password in candidate_password_list:
            self.check_password(password)
            if (check_reversed):
                self.check_password(password[::-1])

    def check_password(self, password):
        if (password in self.found_passwords):
            return
        hashed_password = self.raw_password_to_hash(password)
        if (hashed_password in self.hash_keys.keys()):
            self.found_passwords.add(password)
            self.num_found_passwords += self.hash_keys[hashed_password].count

    def raw_password_to_hash(self, raw_password):
        """Generate hash of raw_password. It is assumed we know sha256 is used"""
        return hashlib.pbkdf2_hmac(
            'sha256', raw_password.encode('utf-8'), self.salt, self.iterations)

    @staticmethod
    def read_file(file):
        f = open(file, "r")
        return OfflineDictionaryAttack.read_all_input(f)

    @staticmethod
    def read_all_input(file):
        all_inputs = []
        while True:
            try:
                c_input = file.readline().rstrip().lstrip()
                if c_input.strip() != '':
                    all_inputs.append(c_input)
                else:
                    break
            except ValueError:
                print("Invalid Input")
        return all_inputs


if __name__ == "__main__":
    security_account_manager = SecurityAccountManager()
    offline_dictionary_attack = OfflineDictionaryAttack(
        security_account_manager)
