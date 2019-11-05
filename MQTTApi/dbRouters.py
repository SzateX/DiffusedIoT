class MQTTApiDbRouter:
    app_labels = ['MQTTApi']
    db_key_name = 'hub_db'
    
    def db_for_read(self, model, **hints):
        if model._meta.app_label in self.app_labels:
            return self.db_key_name
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label in self.app_labels:
            return self.db_key_name
        return None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._meta.app_label in self.app_labels and \
           obj2._meta.app_label in self.app_labels:
           return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label in self.app_labels:
            return db == self.db_key_name
        return None