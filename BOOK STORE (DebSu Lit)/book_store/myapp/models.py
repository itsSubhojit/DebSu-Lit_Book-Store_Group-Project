from django.db import models
from django.contrib.auth.models import AbstractUser


# Create your models here.
class CustomUser(AbstractUser):
    mobile = models.CharField(max_length=10, blank=True, default='')
    is_google_user = models.BooleanField(default=False, verbose_name="Sign in via Google")
    address_line1 = models.CharField(max_length=255, null=True, blank=True)
    address_line2 = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    state = models.CharField(max_length=100, null=True, blank=True)
    pincode = models.CharField(max_length=10, null=True, blank=True)

    @property
    def full_address(self):
        parts = [self.address_line1, self.address_line2, self.city, self.state, self.pincode]
        valid_parts = [p.strip() for p in parts if p and p.strip()]
        return ", ".join(valid_parts) if valid_parts else ""


class Student(models.Model):
    name=models.CharField(max_length=200)
    email=models.CharField(max_length=255, unique=True)
    mobile=models.CharField(max_length=10)
    
class Category(models.Model):
    cat_name=models.CharField(max_length=255)
    abt_cat=models.TextField()
    def __str__(self):
        return self.cat_name

class Item(models.Model):
    name=models.CharField(max_length=255)
    description=models.TextField()
    author=models.CharField(max_length=255)
    publisher=models.CharField(max_length=255)
    pub_date=models.CharField(max_length=10)
    price=models.CharField(max_length=255)
    edition=models.CharField(max_length=100)
    b_img=models.ImageField(upload_to='items/')
    category=models.ForeignKey(Category, on_delete=models.CASCADE)
    isbn = models.CharField(max_length=13, unique=True, null=True, blank=True)# ISBN is typically 13 characters
    page_no = models.IntegerField(default=1)
    language = models.CharField(max_length=50, default="English")  # Change the default as needed
    binding = models.CharField(max_length=50, default="Paperback")

    
class CartItem(models.Model):
	item = models.ForeignKey(Item, on_delete=models.CASCADE)
	quantity = models.PositiveIntegerField(default=0)
	user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
	date_added = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return f'{self.quantity} x {self.item.name}'
     

class Order(models.Model):
    order_id = models.CharField(max_length=50, null=True, blank=True, db_index=True)
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=0)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    date_ordered = models.DateTimeField(auto_now_add=True)
    payment_status=models.CharField(max_length=255)
    payment_id=models.CharField(max_length=255)
    address=models.TextField()

    def __str__(self):
        return f"{self.order_id or self.id} - {self.item.name} ({self.user.username})"



