from django.urls import path
from . import views

urlpatterns=[
    path('', views.home, name='hmpage'),
    path('about', views.about, name='aboutpage'),
    path('useraccount', views.useraccount, name='useraccountpage'),
    path('login', views.signIn, name='loginpage'),
    path('signup', views.signup, name='signuppage'),
    path('forgotpassword', views.forgotpassword, name='forgotpasswordpage'),
    path('orders', views.orders, name='orderspage'),
    path('shoppingcart', views.shoppingcart, name='shoppingcartpage'),
    path('featured', views.featured, name='featuredpage'),
    path('arrivals/<int:id>/', views.arrivals, name='arrivalspage'),
    path('logout', views.signOut, name='logout'),
    path('stdreg', views.stdReg, name='std-reg'),
    path('stdlist', views.stdList, name='std-list'),
    path('stddel/<int:id>', views.stdDel, name='std-del'),
    path('stdupd/<int:id>', views.stdUpd, name='std-upd'),
    path('stdAdmin', views.stdAdmin, name='std-Admin'),
    path('featuresbook1/<int:item_id>/', views.featuresbook1, name='featuresbook1page'),
    path('add/<int:item_id>/', views.add_to_cart, name='add_to_cart'),
    path('buy-now/<int:item_id>/', views.buy_now, name='buy_now'),
    path('cart', views.view_cart, name='view_cart'),
    path('remove/<int:id>', views.remove_cart, name='remove_cart'),
    path("initiate-payment/", views.initiate_payment, name="initiate_payment"),
    path("verify-payment/", views.verify_payment, name="verify_payment"),
    path("payment-success/", views.payment_success, name="payment_success"),
    path("payment-failed/", views.payment_failed, name="payment_failed"),
    path("retry-payment/", views.view_cart, name="retry_payment"),
    path("myorder/", views.myOrders, name="my-orders"),
    path("health/", views.health_check, name="health_check"),
    path("health", views.health_check, name="health_check_no_slash"),
    path("auth/google/", views.google_login, name="google_oauth_login"),
    path("auth/google/callback/", views.google_callback, name="google_oauth_callback"),
]


