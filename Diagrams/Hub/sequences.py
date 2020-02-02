import napkin


@napkin.seq_diagram()
def log_in(c):
    user = c.object('User')
    hub = c.object('Hub')



@napkin.seq_diagram()
def distributed_control(c):
    user = c.object('User')
    order = c.object('Order')
    orderLine = c.object('OrderLine')
    product = c.object('Product')
    customer = c.object('Customer')

    with user:
        with order.calculatePrice():
            with orderLine.calculatePrice():
                product.getPrice('quantity:number')
                with customer.getDiscountedValue(order):
                    order.getBaseValue().ret('value')
                    c.ret('discountedValue')