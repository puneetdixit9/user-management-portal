from flask import g
from flask_sqlalchemy import SQLAlchemy

from main.utils import get_query_including_filters

db = SQLAlchemy()


class BaseModel(db.Model):
    __abstract__ = True

    created_on = db.Column(db.DateTime, server_default=db.func.now())
    created_by = db.Column(db.String(50))
    modified_on = db.Column(db.DateTime, default=None, onupdate=db.func.now())
    modified_by = db.Column(db.String(50))

    @classmethod
    def create(cls, data: dict) -> db.Model:
        """
        To create the record.
        :param data:
        :return:
        """
        if hasattr(g, "user"):
            data["created_by"] = g.user.email
        record = cls(**data)
        db.session.add(record)
        db.session.commit()
        return record

    @classmethod
    def get_all(cls, to_json=False) -> list:
        """
        To get all records
        """
        records = cls.query.all()
        return [record.serialize() for record in records] if to_json else records

    @classmethod
    def get(cls, _id, to_json=False) -> dict or None:
        record = cls.query.get(_id)
        if not to_json:
            return record
        if record and to_json:
            return record.serialize()
        return None

    @classmethod
    def filter(cls, only_first=False, to_json=False, **filters):
        query = cls.query.filter_by(**{k: v for k, v in filters.items() if hasattr(cls, k)})
        if not only_first:
            records = query.all()
            if to_json:
                return [record.serialize() for record in records]
            return [record for record in records]
        record = query.first()
        if to_json:
            if record:
                return record.serialize()
        return record

    @classmethod
    def nested_filter(cls, filters_dict: dict, only_first=False):
        """
        To get filtered records.
        """
        query = get_query_including_filters(db, cls, filters_dict)
        if not only_first:
            return [record.serialize() for record in cls.query.all()]
        record = query.first()
        if record:
            return record.serialize()
        return None

    def update(self, data: dict):
        """
        To update the record.
        :param data:
        :return:
        """
        if hasattr(g, "user"):
            data["modified_by"] = g.user.email
        for k, v in data.items():
            if hasattr(self, k):
                setattr(self, k, v)
        db.session.commit()

    @classmethod
    def delete(cls, **filters):
        """
        To delete the records based on filters.
        :param filters:
        :return:
        """
        db.session.query(cls).filter_by(**filters).delete()
        db.session.commit()

    def serialize(self) -> dict:
        """
        To convert the model object to a dict.
        :return:
        """
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
