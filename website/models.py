from .database import usersCollection
from bson import ObjectId  # Make sure to import ObjectId if _id is an ObjectId

usersSchema = {
    "name": None,
    "username": None,
    "password": None,
    "email": None,
    "translation_history": []
}

def create_user(name, username, password_hash, email):
    data = usersSchema.copy()
    data['name'] = name
    data['username'] = username
    data['password'] = password_hash
    data['email'] = email
    data['translation_history'] = []
    return usersCollection.insert_one(data)

def get_user(username):
    return usersCollection.find_one({'username': username})

def get_user_by_email(email):
    return usersCollection.find_one({'email': email})

def get_user_by_id(user_id):
    return usersCollection.find_one({'_id': ObjectId(user_id)})

def add_translation_to_history(username, original_text, translated_text):
    usersCollection.update_one(
        {'username': username},
        {'$push': {'translation_history': {'original_text': original_text, 'translated_text': translated_text}}}
    )

def get_translation_history(username):
    user = get_user(username)
    return user.get('translation_history', []) if user else []

def reset_user_password(email, new_password_hash):
    result = usersCollection.update_one(
        {'email': email},
        {'$set': {'password': new_password_hash}}
    )
    return result.modified_count > 0
