#!/usr/bin/env python3
"""
DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from user import Base, User


class DB:
    """DB class
    """
    def __init__(self) -> None:
        """
        Constructor
        """
        self._engine = create_engine("sqlite:///a.db")
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """
        Initialize a new DB instance
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Memoized session object
        """
        new_user = User(email=email, hashed_password=hashed_password)
        self._session.add(new_user)
        self._session.commit()

        return new_user

    def find_user_by(self, **kwargs) -> User:
        """
        This method takes in arbitrary keyword arguments
        and returns the first row found in the users table
        """
        try:
            user_filter = self._session.query(User).filter_by(**kwargs).first()
        except TypeError:
            raise InvalidRequestError

        if user_filter is None:
            raise NoResultFound

        return user_filter

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        update the properties of a user
        """
        user = self.find_user_by(id=user_id)
        names_columns = User.__table__.columns.keys()

        for key in kwargs.keys():
            if key not in names_columns:
                raise ValueError

        for key, value in kwargs.items():
            setattr(user, key, value)
