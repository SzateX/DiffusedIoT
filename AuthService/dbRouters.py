"""class AuthDbRouter:
    app_labels = ['AuthService', 'guardian', 'auth', 'contenttypes']
    def db_for_read(self, model, **hints):
        if model._meta.app_label in self.app_labels:
            return 'auth_db'
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label in self.app_labels:
            return 'auth_db'
        return None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._meta.app_label in self.app_labels or \
           obj2._meta.app_label in self.app_labels:
           return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        print(app_label)
        if app_label in self.app_labels:
            return db == 'auth_db'
        return None"""