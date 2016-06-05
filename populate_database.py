from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Item, Category, User, Base


engine = create_engine('sqlite:///itemcatalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# Clean up everything




# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

categories = []
categories.append(Category(id=0, name="Soccer"))
categories.append(Category(id=1, name="Basketball"))
categories.append(Category(id=2, name="Baseball"))
categories.append(Category(id=3, name="Frisbee"))
categories.append(Category(id=4, name="Snowboarding"))
categories.append(Category(id=5, name="Rock Climbing"))

for category in categories:
       session.add(category)
session.commit()

print "added 6 categories"

items = []
items.append(Item(name="Baseball bat", user_id=1, description="Just an ordinary baseball bat", category_id=2))
items.append(Item(name="Soccer ball", user_id=1, description="Just an ordinary football", category_id=0))
items.append(Item(name="Snowboard", user_id=1, description="Just an ordinary board", category_id=4))
items.append(Item(name="Frisbee", user_id=1, description="Just an ordinary frisbee", category_id=3))

for item in items:
       session.add(item)
session.commit()

print "added 4 items"