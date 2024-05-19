import time

def time_it(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()  
        result = func(*args, **kwargs) 
        end_time = time.time()
        print(f"Executing {func.__name__} took {end_time - start_time:.4f} seconds.")
        return result
    return wrapper
