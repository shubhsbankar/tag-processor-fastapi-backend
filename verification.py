from database import verify_uid_in_database
def verify_data(uid):
    # Implement your verification logic here
    data = verify_uid_in_database(uid)
    print("data : ",data)
    score = 0
    if data:  # Placeholder
        score += 4
    else:
        score -= 3
    print("score : ",score)


